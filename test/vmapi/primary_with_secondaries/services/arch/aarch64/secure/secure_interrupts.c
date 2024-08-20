/*
 * Copyright 2023 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/vm/interrupts.h"

#include "hf/ffa.h"
#include "hf/mm.h"

#include "vmapi/hf/call.h"

#include "../smc.h"
#include "sp805.h"
#include "test/hftest.h"
#include "test/vmapi/arch/exception_handler.h"
#include "test/vmapi/ffa.h"

#define PLAT_ARM_TWDOG_BASE 0x2a490000
#define PLAT_ARM_TWDOG_SIZE 0x20000
#define ITERATIONS_PER_MS 15000

#define RTM_INIT_ESPI_ID 5000U
#define PLAT_FVP_SEND_ESPI 0x82000100U

static bool rtm_init_espi_handled;

static inline void sp_wait_loop(uint32_t ms)
{
	uint64_t iterations = (uint64_t)ms * ITERATIONS_PER_MS;

	for (volatile uint64_t loop = 0; loop < iterations; loop++) {
		/* Wait */
	}
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

	if (intid == HF_NOTIFICATION_PENDING_INTID) {
		/* RX buffer full notification. */
		HFTEST_LOG("Received notification pending interrupt.");
	} else if (intid == IRQ_TWDOG_INTID) {
		/*
		 * Interrupt triggered due to Trusted watchdog timer expiry.
		 * Clear the interrupt and stop the timer.
		 */
		HFTEST_LOG("Trusted WatchDog timer stopped: %u", intid);
		sp805_twdog_stop();

		/* Perform secure interrupt de-activation. */
		ASSERT_EQ(hf_interrupt_deactivate(intid), 0);
	} else if (intid == RTM_INIT_ESPI_ID) {
		HFTEST_LOG("interrupt id: %u", intid);
		ASSERT_EQ(hf_interrupt_deactivate(intid), 0);
		rtm_init_espi_handled = true;
	} else {
		panic("%s: unknown interrupt id.", __func__);
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
	sp805_twdog_refresh();
	sp805_twdog_start((delay * ARM_SP805_TWDG_CLK_HZ) / 1000);

	/* Wait for the interrupt to trigger. */
	sp_wait_loop(delay + 50);

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
