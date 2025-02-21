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
#include "ipi_state.h"
#include "sp805.h"
#include "test/hftest.h"
#include "test/vmapi/arch/exception_handler.h"
#include "test/vmapi/ffa.h"
#include "twdog.h"
#include "twdog_state.h"

#define PLAT_ARM_TWDOG_BASE 0x2a490000
#define PLAT_ARM_TWDOG_SIZE 0x20000
#define ITERATIONS_PER_MS 15000
#define RTM_INIT_ESPI_ID 5000
#define PLAT_FVP_SEND_ESPI 0x82000100U
#define TWDOG_DELAY 50
/**
 * Range of eSPIs registered to the espi_test_node devices
 * for service3.
 */
#define SERVICE3_ESPI_ID_START 5001
#define SERVICE3_ESPI_ID_END 5010

static uint32_t last_interrupt_id;
static bool rtm_init_espi_handled;
static bool managed_exit_handled;
/**
 * Indicates if to send the next eSPI interrupt
 * when handling one of the espi_test_node interrupts.
 */
static bool send_back_to_back_interrupts;
/**
 * Indicates if to return to the NWd during the back
 * to back tests.
 */
static bool back_to_back_nwd_return;

uint32_t espi_id = RTM_INIT_ESPI_ID;

static bool multiple_interrupts_expected;

static bool arch_timer_expired;

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

/**
 * Utilizes FVP specific SMC call to pend an eSPI interrupt. The
 * SiP function ID 0x82000100 must have been added to SMC whitelist
 * for the SP that invokes it.
 */
static void send_espi(uint32_t espi_id)
{
	struct ffa_value res;

	res = smc32(PLAT_FVP_SEND_ESPI, espi_id, 0, 0, 0, 0, 0, 0);

	if ((int64_t)res.func == SMCCC_ERROR_UNKNOWN) {
		dlog_error("SiP SMC call not supported");
	}
}

TEST_SERVICE(sip_call_trigger_spi)
{
	void *recv_buf = SERVICE_RECV_BUFFER();
	uint32_t interrupt_id;

	/* Retrieve interrupt ID to be triggered. */
	receive_indirect_message((void *)&interrupt_id, sizeof(interrupt_id),
				 recv_buf);

	send_espi(interrupt_id);

	/* Give back control to PVM. */
	ffa_yield();
}

static void irq_handler(void)
{
	uint32_t intid = hf_interrupt_get();
	struct ffa_value ret;
	ffa_id_t own_id = hf_vm_get_id();

	switch (intid) {
	case HF_NOTIFICATION_PENDING_INTID:
		/* RX buffer full notification. */
		dlog_verbose("Received notification pending interrupt %u.",
			     intid);
		break;
	case HF_MANAGED_EXIT_INTID:
		HFTEST_LOG("Received managed exit interrupt. %u.", intid);

		managed_exit_handled = true;

		ret = ffa_msg_send_direct_resp(
			own_id, hftest_get_dir_req_source_id(), 0, 0, 0, 0, 0);
		EXPECT_EQ(ret.func, FFA_MSG_SEND_DIRECT_REQ_32);
		EXPECT_EQ(ret.arg3, 0);
		break;
	case IRQ_TWDOG_INTID:
		/*
		 * Interrupt triggered due to Trusted watchdog timer expiry.
		 * Clear the interrupt and stop the timer.
		 */
		dlog_info("Received Trusted WatchDog Interrupt: %u.", intid);
		twdog_stop();

		/*
		 * Keep the call to hf_interrupt_deactive although it is
		 * deprecated to test backwards compatibility.
		 */
		ASSERT_EQ(hf_interrupt_deactivate(intid), 0);
		/* Perform secure interrupt de-activation. */
		break;
	case RTM_INIT_ESPI_ID:
		dlog_info("Receive ESPI interrupt: %u", intid);
		ASSERT_EQ(hf_interrupt_deactivate(intid), 0);
		rtm_init_espi_handled = true;
		break;
	case SERVICE3_ESPI_ID_START:
	case SERVICE3_ESPI_ID_START + 1:
	case SERVICE3_ESPI_ID_START + 2:
	case SERVICE3_ESPI_ID_START + 3:
	case SERVICE3_ESPI_ID_START + 4:
	case SERVICE3_ESPI_ID_START + 5:
	case SERVICE3_ESPI_ID_START + 6:
	case SERVICE3_ESPI_ID_START + 7:
	case SERVICE3_ESPI_ID_START + 8:
	case SERVICE3_ESPI_ID_START + 9:
	case SERVICE3_ESPI_ID_START + VINT_QUEUE_MAX:
		dlog_info("ESPI interrupt received %u", intid);

		/*
		 * Check the interrupts are handled in the order they were sent.
		 */
		ASSERT_EQ(last_interrupt_id + 1, intid);

		if (send_back_to_back_interrupts &&
		    intid != SERVICE3_ESPI_ID_END) {
			send_espi(intid + 1);

			if (back_to_back_nwd_return) {
				ret = ffa_msg_wait();
				EXPECT_EQ(ret.func, FFA_RUN_32);
			} else {
				/* Wait for the interrupt to trigger. */
				sp_wait(20);
			}
		}
		break;
	case HF_IPI_INTID:
		dlog_info("Received inter-processor interrupt %u, vm %x.",
			  intid, own_id);
		ASSERT_TRUE(hftest_ipi_state_is(SENT) ||
			    (hftest_ipi_state_is(HANDLED) &&
			     hftest_ipi_state_get_interrupt_count() > 0 &&
			     multiple_interrupts_expected));
		hftest_ipi_state_set(HANDLED);
		break;
	default:
		panic("Interrupt ID not recongnised\n");
	}

	last_interrupt_id = intid;
}

/**
 * The interrupt handler for the tests in which an eSPI was used along with
 * interrupt state structures.
 */
void espi_state_irq_handler(void)
{
	uint32_t intid = hf_interrupt_get();

	if (intid == HF_NOTIFICATION_PENDING_INTID) {
		/* RX buffer full notification. */
		dlog_verbose("Received notification pending interrupt %u.",
			     intid);
	} else if (intid == espi_id) {
		dlog_info("Receive ESPI interrupt: %u", intid);
		hftest_ipi_state_set(HANDLED);
	} else {
		panic("Interrupt ID %u not expected\n", intid);
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

	echo_sender = receive_indirect_message(&delay, sizeof(delay), recv_buf)
			      .sender;

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
	send_espi(espi_id);
}

/**
 * Handle interrupt during runtime model init.
 */
SERVICE_SET_UP(handle_interrupt_rtm_init)
{
	/*
	 * Setup handling of known interrupts including Secure Watchdog
	 * timer interrupt and NPI.
	 */
	exception_setup(irq_handler, NULL);
	interrupts_enable();
	EXPECT_EQ(hf_interrupt_enable(espi_id, true, 0), 0);

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

	/*
	 * Set up the irq handler to handle the NPIs recieved from direct
	 * messaging.
	 */
	exception_setup(irq_handler, NULL);
	interrupts_enable();

	/* Obtain the ID of the target service through indirect message. */
	receive_indirect_message((void *)&target_vm_id, sizeof(target_vm_id),
				 recv_buf);

	ret = ffa_msg_wait();
	EXPECT_EQ(ret.func, FFA_RUN_32);

	/*
	 * Get the shared page used for interrupt status coordination and track
	 * it.
	 */
	hftest_twdog_state_page_setup(recv_buf, send_buf);
	ASSERT_TRUE(hftest_twdog_state_is(INIT));

	ret = ffa_msg_wait();
	EXPECT_EQ(ret.func, FFA_RUN_32);

	ret = ffa_msg_send_direct_req(hf_vm_get_id(), target_vm_id, msg[0],
				      msg[1], msg[2], msg[3], msg[4]);

	/* The target SP is expected to yield its CPU cycles. */
	EXPECT_EQ(ret.func, FFA_YIELD_32);

	ASSERT_TRUE(hftest_twdog_state_is(SENT));

	/* Wait for TWDOG secure physical interrupt to trigger. */
	sp_wait(TWDOG_DELAY + 5);

	/*
	 * SPMC would have queued the virtual interrupt for the target SP.
	 * Hence the interrupt status should not have changed.
	 */
	ASSERT_TRUE(hftest_twdog_state_is(SENT));

	ret = ffa_run(target_vm_id, 0);
	EXPECT_EQ(ret.func, FFA_MSG_SEND_DIRECT_RESP_32);

	/* The target SP must have serviced the interrupt by now. */
	ASSERT_TRUE(hftest_twdog_state_is(HANDLED));

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
		hftest_twdog_state_set(HANDLED);

		/* Perform secure interrupt de-activation. */
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

	/*
	 * Get the shared page used for interrupt status coordination and track
	 * it.
	 */
	hftest_twdog_state_page_setup(recv_buf, send_buf);

	/*
	 * Ensure the status of the interrupt is correct before the test begins.
	 */
	ASSERT_TRUE(hftest_twdog_state_is(INIT));

	ret = ffa_msg_wait();

	/* The companion SP sends a direct request message. */
	EXPECT_EQ(ret.func, FFA_MSG_SEND_DIRECT_REQ_32);

	/* Program the trusted watchdog timer and yield to companion SP. */
	dlog_verbose("Start TWDOG timer with a delay of %lu\n", ret.arg3);
	twdog_start((ret.arg3 * ARM_SP805_TWDG_CLK_HZ) / 1000);

	hftest_twdog_state_set(SENT);

	/* Yield the direct request thereby moving to BLOCKED state. */
	ffa_yield();

	dlog_verbose("Completing the direct response.\n");
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
	ffa_vcpu_index_t target_vcpu_ids[MAX_CPUS];
	struct ffa_value ret;

	dlog_verbose("Receiving ID of target vCPU...");

	ret = ffa_msg_wait();
	EXPECT_EQ(ret.func, FFA_RUN_32);

	receive_indirect_message(&target_vcpu_ids, sizeof(target_vcpu_ids),
				 SERVICE_RECV_BUFFER());

	dlog_verbose("Waiting for target vCPUs to be ready.");

	/* Do nothing while IPI handler is not ready. */
	while (!hftest_ipi_state_is(READY)) {
	}

	hftest_ipi_state_set(SENT);

	/* Send IPIs until the first invalid ID. */
	for (int i = 0; i < MAX_CPUS; i++) {
		if (target_vcpu_ids[i] == MAX_CPUS) {
			break;
		}
		dlog_verbose("Sending IPI to vCPU %u", target_vcpu_ids[i]);
		hf_interrupt_send_ipi(target_vcpu_ids[i]);
		multiple_interrupts_expected = i > 0;
	}

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

	/*
	 * Set up the irq handler to handle the NPIs recieved from direct
	 * messaging.
	 */
	exception_setup(irq_handler, NULL);
	interrupts_enable();

	dlog_verbose("Receiving ID of target vCPU...");

	while (true) {
		ret = ffa_msg_wait();
		EXPECT_EQ(ret.func, FFA_RUN_32);

		receive_indirect_message((void *)&vcpu, sizeof(vcpu),
					 SERVICE_RECV_BUFFER());

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
	struct ffa_value ret;

	exception_setup(irq_handler, NULL);
	interrupts_enable();

	/* Enable the inter-processor interrupt */
	EXPECT_EQ(hf_interrupt_enable(HF_IPI_INTID, true, INTERRUPT_TYPE_IRQ),
		  0);

	ret = ffa_msg_wait();
	EXPECT_EQ(ret.func, FFA_RUN_32);

	hftest_ipi_init_state_from_message(SERVICE_RECV_BUFFER(),
					   SERVICE_SEND_BUFFER());

	/* Yield such that 'send_ipi' can be spawn. */
	ffa_yield();

	hftest_ipi_state_set_all_ready();

	dlog_verbose("Waiting for the IPI\n");

	/* Waiting for irq_handler to handle IPI. */
	while (!hftest_ipi_state_is(HANDLED)) {
		interrupt_wait();
	}

	hftest_ipi_state_set(READY);

	ffa_yield();
}

/**
 * Test service to check that secure interrupts do not interfere with IPIs and
 * vice versa.
 * - Configures the IPI VI.
 * - Yield back to the NWd, such that it can spawn 'send_ipi' in the source
 *   vCPU.
 * - Wakes up and triggers a TWDOG secure interrupt.
 * - Once this is received transition the IPI state to READY.
 * - Loop into waiting for IPI handler to set IPI state to HANDLED.
 * - Sets the IPI state to READY for any future tests.
 * - Triggers another TWDOG secure interrupt to ensure this is also received as
 * normal.
 */
TEST_SERVICE(receive_ipi_running_with_secure_interrupts)
{
	struct ffa_value ret;
	uint32_t delay = 50;

	exception_setup(irq_handler, NULL);
	interrupts_enable();

	/* Enable the Secure Watchdog timer interrupt. */
	EXPECT_EQ(hf_interrupt_enable(IRQ_TWDOG_INTID, true, 0), 0);
	/* Enable the inter-processor interrupt. */
	EXPECT_EQ(hf_interrupt_enable(HF_IPI_INTID, true, INTERRUPT_TYPE_IRQ),
		  0);

	ret = ffa_msg_wait();
	EXPECT_EQ(ret.func, FFA_RUN_32);

	hftest_ipi_init_state_from_message(SERVICE_RECV_BUFFER(),
					   SERVICE_SEND_BUFFER());

	/* Yield such that 'send_ipi' can be spawn. */
	ffa_yield();

	/* Throw a secure interrupt other than the IPI. */
	twdog_refresh();
	twdog_start((delay * ARM_SP805_TWDG_CLK_HZ) / 1000);

	/* Wait for the interrupt to trigger. */
	sp_wait(delay + 50);

	hftest_ipi_state_set_all_ready();

	dlog_verbose("Waiting for the IPI\n");

	/* Waiting for irq_handler to handle IPI. */
	while (!hftest_ipi_state_is(HANDLED)) {
		interrupt_wait();
	}

	hftest_ipi_state_set(READY);

	/* Throw a secure interrupt other than the IPI. */
	twdog_refresh();
	twdog_start((delay * ARM_SP805_TWDG_CLK_HZ) / 1000);

	/* Wait for the interrupt to trigger. */
	sp_wait(delay + 50);

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

	/*
	 * Set up the irq handler to handle the NPIs recieved from direct
	 * messaging.
	 */
	exception_setup(irq_handler, NULL);
	interrupts_enable();

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

/**
 * Service to test that interrupts are handled when fired while in the
 * waiting state.
 * - Configures the irq handler. IRQ is enabled in
 * SERVICE_SET_UP(handle_interrupt_rtm_init).
 * - Goes to waiting state so it can receive the interrupt state structure.
 * - Wakes up and configures the state to ready, such that sender can trigger
 *   the ESPI.
 * - FFA_MSG_WAIT invoked to put the SP in waiting state. At this point,
 *   PVM should resume sender for triggering the ESPI.
 * - Service wakes up expecting to handle the interrupt, attests interrupt
 *   state is HANDLED, which indicates execution has reached the IRQ
 *   handler.
 */
TEST_SERVICE(receive_interrupt_waiting_vcpu_sri_triggered)
{
	exception_setup(espi_state_irq_handler, NULL);
	interrupts_enable();
	EXPECT_EQ(hf_interrupt_enable(espi_id, true, 0), 0);

	dlog_info("Enabled ESPI. Waiting for interrupt state.");

	EXPECT_EQ(ffa_msg_wait().func, FFA_RUN_32);

	/* Configures the Interrupt state. */
	hftest_ipi_init_state_from_message(SERVICE_RECV_BUFFER(),
					   SERVICE_SEND_BUFFER());

	hftest_ipi_state_set(READY);

	dlog_info("Received the interrupt state. Waiting for interrupt.");

	/* Set vCPU in waiting. */
	EXPECT_EQ(ffa_msg_wait().func, FFA_RUN_32);

	/* Attest that ESPI is handled. */
	dlog_info("Woke up. Waiting for ESPI to be handled.");

	while (!hftest_ipi_state_is(HANDLED)) {
	}

	ffa_yield();

	FAIL("Do not expect getting to this point.");
}

void arch_timer_irq_handler(void)
{
	uint32_t intid = hf_interrupt_get();

	switch (intid) {
	case HF_NOTIFICATION_PENDING_INTID:
		/* RX buffer full notification. */
		dlog_verbose("Received notification pending interrupt %u.",
			     intid);
		break;
	case HF_VIRTUAL_TIMER_INTID:
		dlog_info("Receive Arch Timer interrupt.");
		arch_timer_expired = true;
		timer_disable();
		break;
	default:
		panic("Interrupt ID not recongnised\n");
	}
}

TEST_SERVICE(receive_interrupt_sri_triggered_into_waiting_arch_timer)
{
	exception_setup(arch_timer_irq_handler, NULL);
	interrupts_enable();
	EXPECT_EQ(hf_interrupt_enable(HF_VIRTUAL_TIMER_INTID, true, 0), 0);

	dlog_info("Starting arch timer.");

	timer_set(50);
	timer_start();

	EXPECT_EQ(ffa_msg_wait().func, FFA_RUN_32);

	dlog_info("Woke up");

	ASSERT_TRUE(arch_timer_expired);

	/* Attest it has been handled. */
	ffa_yield();

	FAIL("Do not expect getting to this point.");
}

/**
 * Service function to test SRI is triggered when SP goes back into
 * waiting state with pending interrupts.
 * - Configures the respective IRQ handler.
 * - Enables ESPI 5001.
 * - Unmasks interrupts, so it can acknowledg the NPI.
 * - Goes into waiting state to receive interrupt state structure.
 * - Wakes up and retrieves the memory with the shared state structure.
 * - Sets the state to ready since it can now handle interrupts.
 * - Masks interrupts such that the next time it resumes, the interrupt
 *   will remain pending.
 * - Wakes up with FFA_INTERRUPT. Do not call hf_interrupt_get and go back
 *   to wait.
 * - Wake up and attest the state is "SENT".
 * - With interrupt pending go back to waiting state.
 * - Wake up and enable interrupts. The ESPI shall be handled. Attest by
 *   checking interrupt state is Handled.
 * - Terminates the test.
 */
TEST_SERVICE(receive_interrupt_sri_triggered_into_waiting)
{
	/*
	 * Interrupt assigned to service3, who is excepted to run this
	 * test.
	 */
	espi_id = SERVICE3_ESPI_ID_START;
	exception_setup(espi_state_irq_handler, NULL);

	EXPECT_EQ(hf_interrupt_enable(espi_id, true, 0), 0);

	/* So it handles the NPI. */
	interrupts_enable();

	dlog_info("Waiting for interrupt state.");

	EXPECT_EQ(ffa_msg_wait().func, FFA_RUN_32);

	/* Configures the interrupt state. */
	hftest_ipi_init_state_from_message(SERVICE_RECV_BUFFER(),
					   SERVICE_SEND_BUFFER());

	hftest_ipi_state_set(READY);

	/* Now NPI is handled, disable interrupts. */
	interrupts_disable();

	dlog_info("Received the interrupt state. Masked Interrupts.");

	/* It will be entered with FFA_INTERRUPT_32. */
	EXPECT_EQ(ffa_msg_wait().func, FFA_INTERRUPT_32);

	/* Go back straight to sleep. This should trigger the SRI. */
	EXPECT_EQ(ffa_msg_wait().func, FFA_RUN_32);

	EXPECT_TRUE(hftest_ipi_state_is(SENT));

	dlog_info("The ESPI has been sent. Next FFA_MSG_WAIT to trigger SRI.");

	EXPECT_EQ(ffa_msg_wait().func, FFA_RUN_32);

	dlog_info("Woke up to handle ESPI.");

	interrupts_enable();

	while (!hftest_ipi_state_is(HANDLED)) {
	}

	dlog_info("End of test.");

	ffa_yield();

	FAIL("Do not expect getting to this point.");
}

/**
 * Service function to trigger an ESPI. This is to test the case
 * in which an SP configured itself to be given CPU cycles by the
 * scheduler to handle interrupts, when in waiting state/getting
 * into waiting state.
 * - Sets up interrupt handler for acknowledgin NPI.
 * - FFA_MSG_WAIT so it can receive the interrupt state.
 * - Wakes up, retrieves the memory region with the interrupt state.
 * - Calls again FFA_MSG_WAIT so it receives the ESPI ID to trigger.
 * - Wakes up, waits for the interrupt state to be READY. Once that
 *   is the case, sent the ESPI and set sate to SENT.
 * - Terminates the test.
 */
TEST_SERVICE(send_espi_interrupt)
{
	uint32_t to_send_espi;

	dlog_info("Waiting for interrupt state.");

	exception_setup(irq_handler, NULL);
	interrupts_enable();

	EXPECT_EQ(ffa_msg_wait().func, FFA_RUN_32);
	/* Configures the Interrupt state. */
	hftest_ipi_init_state_from_message(SERVICE_RECV_BUFFER(),
					   SERVICE_SEND_BUFFER());

	dlog_info("Interrupt state obtained. Waiting for interrupt ID.");

	EXPECT_EQ(ffa_msg_wait().func, FFA_RUN_32);

	receive_indirect_message(&to_send_espi, sizeof(to_send_espi),
				 SERVICE_RECV_BUFFER());

	dlog_info("Interrupt ID %u\n", to_send_espi);

	/* Wait for next FFA_RUN to set ESPI. */
	EXPECT_EQ(ffa_msg_wait().func, FFA_RUN_32);

	dlog_info("Wake up to send eSPI.");

	/* Do nothing while ESPI handler is not ready. */
	while (!hftest_ipi_state_is(READY)) {
	}

	/* Set ESPI and transition the state to 'SENT'. */
	hftest_ipi_state_set(SENT);

	send_espi(to_send_espi);

	ffa_yield();

	FAIL("Do not expect getting to this point.");
}

static bool self_ipi_triggered;

static void self_ipi_irq_hander(void)
{
	uint32_t intid = hf_interrupt_get();

	switch (intid) {
	case HF_NOTIFICATION_PENDING_INTID:
		/* RX buffer full notification. */
		dlog_verbose("Received notification pending interrupt %u.",
			     intid);
		break;
	case HF_IPI_INTID:
		dlog_info("Received inter-processor interrupt %u, vm %x.",
			  intid, hf_vm_get_id());
		self_ipi_triggered = true;
		break;
	default:
		panic("Interrupt ID not recongnised\n");
	}
}

TEST_SERVICE(self_ipi)
{
	exception_setup(self_ipi_irq_hander, NULL);
	interrupts_enable();

	/* Enable the inter-processor interrupt */
	EXPECT_EQ(hf_interrupt_enable(HF_IPI_INTID, true, INTERRUPT_TYPE_IRQ),
		  0);

	/* Get the ID here. */
	hf_interrupt_send_ipi(0);

	/* Waiting for self_ipi_irq_hander to handle IPI. */
	while (!self_ipi_triggered) {
	}

	ffa_yield();

	FAIL("Do not expect getting to this point.");
}

/**
 * Test that back to back interrupts received whilst the last interrupt is
 * being handled are all received.
 * - Enable the eSPIs.
 * - Send the first eSPI.
 * - The interrupt handler will send the next eSPI until the last eSPI is
 *   received.
 */
TEST_SERVICE(receive_back_to_back_interrupts)
{
	void *recv_buf = SERVICE_RECV_BUFFER();

	exception_setup(irq_handler, NULL);
	interrupts_enable();

	send_back_to_back_interrupts = true;

	for (int i = SERVICE3_ESPI_ID_START; i <= SERVICE3_ESPI_ID_END; i++) {
		EXPECT_EQ(hf_interrupt_enable(i, true, 0), 0);
	}

	/* Retrieve interrupt ID to be triggered. */
	receive_indirect_message((void *)&back_to_back_nwd_return,
				 sizeof(back_to_back_nwd_return), recv_buf);

	/*
	 * Set last interrupt ID to 5000 so the first eSPI ID of 5001 will
	 * pass the assert that interrupts are handled in the correct order.
	 */
	last_interrupt_id = 5000;

	send_espi(SERVICE3_ESPI_ID_START);

	sp_wait(20);

	/* Check interrupt queue is empty. */
	EXPECT_EQ(hf_interrupt_get(), HF_INVALID_INTID);

	ffa_yield();
}

/**
 * Used to test managed exit.
 * The interrupt is enabled based on arg3 in the direct request,
 * and then the SP enters a busy loop while waiting for the Arch Timer
 * in the NWd to trigger its interrupt. After the loop, we check whether
 * the interrupt handler was entered, depending on if the ME interrupt
 * was enabled, and then return to the NWd. This process is repeated
 * so we can verify that interrupts do not accumulate when the ME interrupt
 * is masked.
 */
TEST_SERVICE(sp_managed_exit_loop)
{
	bool me_enabled;
	struct ffa_value ret;

	exception_setup(irq_handler, NULL);
	interrupts_enable();

	/* Return to the NWd for the Arch Timer to be started. */
	ret = ffa_msg_wait();

	while (true) {
		EXPECT_EQ(ret.func, FFA_MSG_SEND_DIRECT_REQ_32);
		me_enabled = ret.arg3;

		hftest_set_dir_req_source_id(ffa_sender(ret));

		EXPECT_EQ(hf_interrupt_enable(HF_MANAGED_EXIT_INTID, me_enabled,
					      0),
			  0);

		/* Enter busy loop to wait for NWd interrupt. */
		sp_wait(20);

		EXPECT_EQ(managed_exit_handled, me_enabled);

		ret = ffa_msg_send_direct_resp(hf_vm_get_id(),
					       hftest_get_dir_req_source_id(),
					       0, 0, 0, 0, 0);
	}
}

/**
 * Fill the interrupt queue with eSPIs whilst interrupts are disabled.
 * For service3 when entering the waiting state this will case an SRI
 * as the SP has interrupts pending. When we return back to the NWd
 * enable interrupts and ensure all the eSPIs are handled and that
 * they are handled in the order they were sent.
 */
TEST_SERVICE(receive_interrupt_burst)
{
	/*
	 * Interrupt assigned to service3, who is excepted to run this
	 * test.
	 */
	exception_setup(irq_handler, NULL);

	ASSERT_EQ(SERVICE3_ESPI_ID_END - SERVICE3_ESPI_ID_START,
		  VINT_QUEUE_MAX - 1);

	for (int i = SERVICE3_ESPI_ID_START; i <= SERVICE3_ESPI_ID_END; i++) {
		EXPECT_EQ(hf_interrupt_enable(i, true, 0), 0);
	}

	interrupts_disable();

	/* Fill the queue with eSPI interrupts. */
	for (int i = SERVICE3_ESPI_ID_START; i <= SERVICE3_ESPI_ID_END; i++) {
		send_espi(i);
	}

	/* Go back straight to sleep. This should trigger the SRI. */
	EXPECT_EQ(ffa_msg_wait().func, FFA_RUN_32);

	dlog_info("Woke up to handle eSPIs.");

	/*
	 * Set last interrupt ID to 5000 so the first eSPI ID of 5001 will
	 * pass the assert that interrupts are handled in the correct order.
	 */
	last_interrupt_id = 5000;

	interrupts_enable();

	dlog_info("End of test.");

	ffa_yield();

	FAIL("Do not expect getting to this point.");
}

TEST_SERVICE(self_ipi_sri_triggered)
{
	interrupts_disable();
	exception_setup(self_ipi_irq_hander, NULL);

	/* Enable the inter-processor interrupt */
	EXPECT_EQ(hf_interrupt_enable(HF_IPI_INTID, true, INTERRUPT_TYPE_IRQ),
		  0);

	dlog_info("Triggering the IPI to self. Interrupts masked.");

	hf_interrupt_send_ipi(0);

	/* Expect wake up with FFA_RUN. */
	EXPECT_EQ(ffa_msg_wait().func, FFA_RUN_32);

	dlog_info("Woke up. Unmasking interrupts.");

	/* Triggering the IPI to itself. */
	interrupts_enable();

	/* Waiting for self_ipi_irq_hander to handle IPI. */
	while (!self_ipi_triggered) {
	}

	ffa_yield();

	FAIL("Do not expect getting to this point.");
}
