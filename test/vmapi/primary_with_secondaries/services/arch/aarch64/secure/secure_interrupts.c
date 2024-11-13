/*
 * Copyright 2023 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/vm/interrupts.h"
#include "hf/arch/vm/timer.h"

#include "hf/ffa.h"
#include "hf/mm.h"

#include "vmapi/hf/call.h"

#include "../smc.h"
#include "interrupt_status.h"
#include "ipi_state.h"
#include "sp805.h"
#include "test/hftest.h"
#include "test/vmapi/arch/exception_handler.h"
#include "test/vmapi/ffa.h"
#include "twdog.h"

#define PLAT_ARM_TWDOG_BASE 0x2a490000
#define PLAT_ARM_TWDOG_SIZE 0x20000
#define ITERATIONS_PER_MS 15000

#define RTM_INIT_ESPI_ID 5000U
#define PLAT_FVP_SEND_ESPI 0x82000100U
#define TWDOG_DELAY 50

static bool rtm_init_espi_handled;

static inline uint64_t physicalcounter_read(void)
{
	isb();
	return read_msr(cntpct_el0);
}

static inline uint64_t sp_wait(uint32_t ms)
{
	uint64_t timer_freq = read_msr(cntfrq_el0);

	uint64_t time1 = physicalcounter_read();
	volatile uint64_t time2 = time1;

	while ((time2 - time1) < ((ms * timer_freq) / 1000U)) {
		time2 = physicalcounter_read();
	}

	return ((time2 - time1) * 1000) / timer_freq;
}

TEST_SERVICE(sip_call_trigger_spi)
{
	void *recv_buf = SERVICE_RECV_BUFFER();
	struct ffa_value res;
	uint32_t interrupt_id;

	/* Retrieve interrupt ID to be triggered. */
	receive_indirect_message((void *)&interrupt_id, sizeof(interrupt_id),
				 recv_buf, NULL);

	/*
	 * The SiP function ID 0x82000100 must have been added to the SMC
	 * whitelist of the SP that invokes it.
	 */
	res = smc32(0x82000100, interrupt_id, 0, 0, 0, 0, 0, 0);

	EXPECT_NE((int64_t)res.func, SMCCC_ERROR_UNKNOWN);

	/* Give back control to PVM. */
	ffa_yield();
}

static void irq_handler(void)
{
	uint32_t intid = hf_interrupt_get();

	switch (intid) {
	case HF_NOTIFICATION_PENDING_INTID:
		/* RX buffer full notification. */
		HFTEST_LOG("Received notification pending interrupt %u.",
			   intid);
		break;
	case IRQ_TWDOG_INTID:
		/*
		 * Interrupt triggered due to Trusted watchdog timer expiry.
		 * Clear the interrupt and stop the timer.
		 */
		HFTEST_LOG("Received Trusted WatchDog Interrupt: %u.", intid);
		twdog_stop();

		/* Perform secure interrupt de-activation. */
		ASSERT_EQ(hf_interrupt_deactivate(intid), 0);
		break;
	case RTM_INIT_ESPI_ID:
		HFTEST_LOG("interrupt id: %u", intid);
		ASSERT_EQ(hf_interrupt_deactivate(intid), 0);
		rtm_init_espi_handled = true;
		break;
	case HF_IPI_INTID:
		HFTEST_LOG("Received Inter-Processor Interrupt %u.", intid);
		ASSERT_TRUE(hftest_ipi_state_is(SENT));
		hftest_ipi_state_set(HANDLED);
		break;
	default:
		panic("Interrupt ID not recongnised\n");
	}
}

TEST_SERVICE(sec_interrupt_preempt_msg)
{
	uint32_t delay;
	struct ffa_value res;
	ffa_id_t echo_sender;
	void *send_buf = SERVICE_SEND_BUFFER();
	void *recv_buf = SERVICE_RECV_BUFFER();
	struct hftest_context *ctx = hftest_get_context();

	dlog_verbose("sec_interrupt_preempt_msg from an S-EL1 partition.");

	/*
	 * Map MMIO address space of peripherals (such as secure
	 * watchdog timer) described as device region nodes in partition
	 * manifest.
	 */
	hftest_map_device_regions(ctx);

	/*
	 * Setup handling of known interrupts including Secure Watchdog timer
	 * interrupt and NPI.
	 */
	exception_setup(irq_handler, NULL);
	interrupts_enable();

	/* Enable the Secure Watchdog timer interrupt. */
	EXPECT_EQ(hf_interrupt_enable(IRQ_TWDOG_INTID, true, 0), 0);

	receive_indirect_message((void *)&delay, sizeof(delay), recv_buf,
				 &echo_sender);

	HFTEST_LOG("Message received: %#x", delay);

	/* Echo message back. */
	send_indirect_message(hf_vm_get_id(), echo_sender, send_buf, &delay,
			      sizeof(delay), 0);

	/* Explicitly mask interrupts to emulate realworld scenario. */
	interrupts_disable();

	/* Start the secure Watchdog timer. */
	HFTEST_LOG("Starting TWDOG: %u ms", delay);
	twdog_refresh();
	twdog_start((delay * ARM_SP805_TWDG_CLK_HZ) / 1000);

	/* Wait for the interrupt to trigger. */
	sp_wait(delay + 50);

	/* Give back control to PVM. */
	res = ffa_msg_wait();

	/* SPMC signals the secure interrupt through FFA_INTERRUPT interface. */
	EXPECT_EQ(res.func, FFA_INTERRUPT_32);

	/*
	 * Unmask the virtual interrupts to allow any pending interrupts to be
	 * serviced.
	 */
	interrupts_enable();

	/* Secure interrupt has been serviced by now. Relinquish cycles. */
	ffa_msg_wait();
}

/**
 * To help testing the handling of secure interrupts during runtime
 * model init.
 * The ESPI interrupt used in this context is assigned to another
 * SP.
 */
SERVICE_SET_UP(send_espi_rtm_init)
{
	struct ffa_value res;

	res = smc32(PLAT_FVP_SEND_ESPI, RTM_INIT_ESPI_ID, 0, 0, 0, 0, 0, 0);

	if ((int64_t)res.func == SMCCC_ERROR_UNKNOWN) {
		HFTEST_LOG("SiP SMC call not supported");
	}
}

/**
 * Handle interrupt during runtime model init.
 */
SERVICE_SET_UP(handle_interrupt_rtm_init)
{
	/*
	 * Setup handling of known interrupts including Secure Watchdog timer
	 * interrupt and NPI.
	 */
	exception_setup(irq_handler, NULL);
	interrupts_enable();
	EXPECT_EQ(hf_interrupt_enable(RTM_INIT_ESPI_ID, true, 0), 0);

	/* Disable such that it doesn't affect Hftest framework. */
	interrupts_disable();
}

/**
 * Check that the interrupt has been handled at runtime initialisation.
 * Service to execute in runtime model of FFA_RUN.
 */
TEST_SERVICE(check_interrupt_rtm_init_handled)
{
	/* Check if the interrupt during initialisation has been handled. */
	EXPECT_TRUE(rtm_init_espi_handled);
	ffa_yield();
}

TEST_SERVICE(send_direct_req_yielded_and_resumed)
{
	struct ffa_value ret;
	ffa_id_t target_vm_id;
	void *send_buf = SERVICE_SEND_BUFFER();
	void *recv_buf = SERVICE_RECV_BUFFER();
	const uint32_t msg[] = {TWDOG_DELAY, 0, 0, 0, 0};

	/* Obtain the ID of the target service through indirect message. */
	receive_indirect_message((void *)&target_vm_id, sizeof(target_vm_id),
				 recv_buf, NULL);

	ret = ffa_msg_wait();
	EXPECT_EQ(ret.func, FFA_RUN_32);

	/* Get the shared page used for interrupt status coordination and track
	 * it. */
	hftest_interrupt_status_page_setup(recv_buf, send_buf);
	EXPECT_EQ(hftest_interrupt_status_get(), INTR_RESET);

	ret = ffa_msg_wait();
	EXPECT_EQ(ret.func, FFA_RUN_32);

	ret = ffa_msg_send_direct_req(hf_vm_get_id(), target_vm_id, msg[0],
				      msg[1], msg[2], msg[3], msg[4]);

	/* The target SP is expected to yield its CPU cycles. */
	EXPECT_EQ(ret.func, FFA_YIELD_32);

	EXPECT_EQ(hftest_interrupt_status_get(), INTR_PROGRAMMED);

	/* Wait for TWDOG secure physical interrupt to trigger. */
	sp_wait(TWDOG_DELAY + 5);

	/*
	 * SPMC would have queued the virtual interrupt for the target SP.
	 * Hence the interrupt status should not have changed.
	 */
	EXPECT_EQ(hftest_interrupt_status_get(), INTR_PROGRAMMED);

	ret = ffa_run(target_vm_id, 0);
	EXPECT_EQ(ret.func, FFA_MSG_SEND_DIRECT_RESP_32);

	/* The target SP must have serviced the interrupt by now. */
	EXPECT_EQ(hftest_interrupt_status_get(), INTR_SERVICED);

	ffa_msg_wait();
	FAIL("Not expected to reach here");
}

static void twdog_irq_handler(void)
{
	uint32_t intid = hf_interrupt_get();

	if (intid == IRQ_TWDOG_INTID) {
		/*
		 * Interrupt triggered due to Trusted watchdog timer expiry.
		 * Clear the interrupt and stop the timer.
		 */
		HFTEST_LOG("Received Trusted WatchDog Interrupt: %u.", intid);
		twdog_stop();

		/* Update the shared interrupt status. */
		hftest_interrupt_status_set(INTR_SERVICED);

		/* Perform secure interrupt de-activation. */
		ASSERT_EQ(hf_interrupt_deactivate(intid), 0);
	} else if (intid == HF_NOTIFICATION_PENDING_INTID) {
		/* RX buffer full notification. */
		HFTEST_LOG("Received notification pending interrupt %u.",
			   intid);
	} else {
		panic("Invalid interrupt received: %u\n", intid);
	}
}

TEST_SERVICE(yield_direct_req_service_twdog_int)
{
	struct ffa_value ret;
	void *send_buf = SERVICE_SEND_BUFFER();
	void *recv_buf = SERVICE_RECV_BUFFER();
	struct hftest_context *ctx = hftest_get_context();

	/*
	 * Map MMIO address space of peripherals (such as secure
	 * watchdog timer) described as device region nodes in partition
	 * manifest.
	 */
	hftest_map_device_regions(ctx);

	exception_setup(twdog_irq_handler, NULL);
	interrupts_enable();

	/* Enable the Secure Watchdog timer interrupt. */
	EXPECT_EQ(hf_interrupt_enable(IRQ_TWDOG_INTID, true, 0), 0);

	ret = ffa_msg_wait();
	EXPECT_EQ(ret.func, FFA_RUN_32);

	/* Get the shared page used for interrupt status coordination and track
	 * it. */
	hftest_interrupt_status_page_setup(recv_buf, send_buf);

	/*
	 * Ensure the status of the interrupt is correct before the test begins.
	 */
	EXPECT_EQ(hftest_interrupt_status_get(), INTR_RESET);

	ret = ffa_msg_wait();

	/* The companion SP sends a direct request message. */
	EXPECT_EQ(ret.func, FFA_MSG_SEND_DIRECT_REQ_32);

	/* Program the trusted watcdog timer and yield to companion SP. */
	HFTEST_LOG("Start TWDOG timer with a delay of %lu", ret.arg3);
	twdog_start((ret.arg3 * ARM_SP805_TWDG_CLK_HZ) / 1000);

	hftest_interrupt_status_set(INTR_PROGRAMMED);

	/* Yield the direct request thereby moving to BLOCKED state. */
	ffa_yield();

	HFTEST_LOG("Completing the direct response");
	ffa_msg_send_direct_resp(ffa_receiver(ret), ffa_sender(ret), ret.arg3,
				 ret.arg4, ret.arg5, ret.arg6, ret.arg7);
	FAIL("Not expected to reach here");
}

/**
 * Test Service to send IPI to a designated vCPU ID.
 * Expects the scheduling endpoint to orchestrate the CPUs
 * and endpoints such that the IPI is sent at the right timing.
 * Assumes the IPI state has been properly instantiated already.
 *
 * - Wakes up and parses the vCPU ID from RX buffer.
 * - Loop IPI state until it gets to READY state.
 * - Transitions the IPI state into SENT.
 * - Sends the IPI to the target vCPU.
 */
TEST_SERVICE(send_ipi)
{
	ffa_vcpu_index_t vcpu;
	struct ffa_value ret;

	dlog_verbose("Receiving ID of target vCPU...");

	ret = ffa_msg_wait();
	EXPECT_EQ(ret.func, FFA_RUN_32);

	receive_indirect_message((void *)&vcpu, sizeof(vcpu),
				 SERVICE_RECV_BUFFER(), NULL);

	dlog_verbose("Waiting for target vCPU %u to be ready.", vcpu);

	/* Do nothing while IPI handler is not ready. */
	while (!hftest_ipi_state_is(READY)) {
	}

	dlog_verbose("Sending IPI to vCPU %u", vcpu);

	hftest_ipi_state_set(SENT);

	hf_interrupt_send_ipi(vcpu);

	ffa_yield();
}

/**
 * Test Service to send IPI to a designated vCPU ID where the send
 * is expect to fail.
 */
TEST_SERVICE(send_ipi_fails)
{
	ffa_vcpu_index_t vcpu;
	struct ffa_value ret;

	dlog_verbose("Receiving ID of target vCPU...");

	while (true) {
		ret = ffa_msg_wait();
		EXPECT_EQ(ret.func, FFA_RUN_32);

		receive_indirect_message((void *)&vcpu, sizeof(vcpu),
					 SERVICE_RECV_BUFFER(), NULL);

		EXPECT_EQ(hf_interrupt_send_ipi(vcpu), -1);
	}
}

/**
 * Test service to valid IPI behaviour when target vCPU is in the running
 * state.
 * - Configures the IPI VI.
 * - Yield back to the NWd, such that it can spawn 'send_ipi' in the source
 *   vCPU.
 * - Wakes up to transitioning the IPI state to READY.
 * - Loop into waiting for IPI handler to set IPI state to HANDLED.
 * - Terminates test by resetting to READY.
 */
TEST_SERVICE(receive_ipi_running)
{
	hftest_ipi_init_state_default();

	exception_setup(irq_handler, NULL);
	interrupts_enable();

	/* Enable the inter-processor interrupt */
	EXPECT_EQ(hf_interrupt_enable(HF_IPI_INTID, true, INTERRUPT_TYPE_IRQ),
		  0);

	/* Yield such that 'send_ipi' can be spawn. */
	ffa_yield();

	hftest_ipi_state_set(READY);

	dlog_verbose("Waiting for the IPI\n");

	/* Waiting for irq_handler to handle IPI. */
	while (!hftest_ipi_state_is(HANDLED)) {
		interrupt_wait();
	}

	hftest_ipi_state_set(READY);

	ffa_yield();
}

/**
 * Test service to validate IPI behaviour when target vCPU is in the waiting
 * state.
 * Transition to READY state is left out of this function. Transitioning
 * into READY is used as synchronisation event for the "send_ipi" function.
 * Given the purpose is to handle in a waiting state, leave transition to READY
 * to external endpoint with same access to IPI state buffer.
 *
 * - Configures the IPI VI, and waits for a message.
 * - Wakes up and attempts to initiate the IPI state in a shared buffer.
 * - Goes into waiting state to fulfill purpose of the test.
 * - Wakes up to attest IPI has been handled.
 */
TEST_SERVICE(receive_ipi_waiting_vcpu)
{
	struct ffa_value ret;

	exception_setup(irq_handler, NULL);
	interrupts_enable();

	/* Enable the IPI. */
	EXPECT_EQ(hf_interrupt_enable(HF_IPI_INTID, true, INTERRUPT_TYPE_IRQ),
		  0);

	dlog_verbose("Waiting memory to instanciate IPI state...\n");

	ret = ffa_msg_wait();
	EXPECT_EQ(ret.func, FFA_RUN_32);

	hftest_ipi_init_state_from_message(SERVICE_RECV_BUFFER(),
					   SERVICE_SEND_BUFFER());

	dlog_verbose("Waiting for the IPI\n");

	/* Get the vCPU into a waiting state before handling IPI. */
	ret = ffa_msg_wait();
	EXPECT_EQ(ret.func, FFA_RUN_32);

	EXPECT_TRUE(hftest_ipi_state_is(HANDLED));

	ffa_yield();
}

/**
 * Test Service to help with testing of IPI when the execution is
 * in the SWd.
 * - Waits for message to retrieve shared buffer where IPI state is
 *   instanciated.
 * - Waits to be resumed again and transition the IPI state into READY.
 */
TEST_SERVICE(set_ipi_ready)
{
	dlog_verbose("%s", __func__);

	/* Ready to receive the memory. */
	ffa_msg_wait();

	/* Configures the ipi state */
	hftest_ipi_init_state_from_message(SERVICE_RECV_BUFFER(),
					   SERVICE_SEND_BUFFER());

	dlog_verbose("IPI state ready\n");

	/* Wait for next FFA_RUN to set ipi state to ready. */
	ffa_msg_wait();

	hftest_ipi_state_set(READY);

	dlog_verbose("Set IPI ready\n");

	while (!hftest_ipi_state_is(HANDLED)) {
	}

	ffa_yield();

	FAIL("Do not expect getting to this point.\n");
}

TEST_SERVICE(receive_ipi_preempted_or_blocked)
{
	struct ffa_value ret;

	hftest_ipi_init_state_default();

	exception_setup(irq_handler, NULL);
	interrupts_enable();

	/* Enable the inter-processor interrupt */
	EXPECT_EQ(hf_interrupt_enable(HF_IPI_INTID, true, INTERRUPT_TYPE_IRQ),
		  0);

	/* Yield such that 'send_ipi' can be spawn. */
	ret = ffa_msg_wait();
	EXPECT_EQ(ret.func, FFA_RUN_32);

	hftest_ipi_init_state_from_message(SERVICE_RECV_BUFFER(),
					   SERVICE_SEND_BUFFER());

	dlog_verbose("Setup the IPI state.");

	ffa_yield();

	dlog_verbose("Waiting for the IPI. Should be preempted before.\n");

	/* Waiting for irq_handler to handle IPI. */
	while (!hftest_ipi_state_is(HANDLED)) {
	}

	hftest_ipi_state_set(READY);

	ffa_yield();
}
