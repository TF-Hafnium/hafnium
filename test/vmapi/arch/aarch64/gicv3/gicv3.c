/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "gicv3.h"

#include "hf/arch/irq.h"
#include "hf/arch/vm/interrupts.h"
#include "hf/arch/vm/interrupts_gicv3.h"

#include "hf/dlog.h"
#include "hf/mm.h"
#include "hf/std.h"

#include "vmapi/hf/call.h"

#include "../msr.h"
#include "test/hftest.h"

alignas(PAGE_SIZE) uint8_t send_page[PAGE_SIZE];
alignas(PAGE_SIZE) uint8_t recv_page[PAGE_SIZE];

hf_ipaddr_t send_page_addr = (hf_ipaddr_t)send_page;
hf_ipaddr_t recv_page_addr = (hf_ipaddr_t)recv_page;

void *send_buffer = send_page;
void *recv_buffer = recv_page;

volatile uint32_t last_interrupt_id = 0;

static void irq(void)
{
	uint32_t interrupt_id = interrupt_get_and_acknowledge();
	dlog("primary IRQ %d from current\n", interrupt_id);
	last_interrupt_id = interrupt_id;
	interrupt_end(interrupt_id);
	dlog("primary IRQ %d ended\n", interrupt_id);
}

void system_setup()
{
	const uint32_t mode = MM_MODE_R | MM_MODE_W | MM_MODE_D;
	hftest_mm_identity_map((void *)GICD_BASE, PAGE_SIZE, mode);
	hftest_mm_identity_map((void *)GICR_BASE, PAGE_SIZE, mode);
	hftest_mm_identity_map((void *)SGI_BASE, PAGE_SIZE, mode);

	exception_setup(irq, NULL);
	interrupt_gic_setup();
}

/* Check that system registers are configured as we expect on startup. */
TEST(system, system_registers_enabled)
{
	/* Check that system register interface to GICv3 is enabled. */
	uint32_t expected_sre =
		1U << 2 | /* Disable IRQ bypass. */
		1U << 1 | /* Disable FIQ bypass. */
		1U << 0;  /* Enable system register interface to GICv3. */
	EXPECT_EQ(read_msr(ICC_SRE_EL1), expected_sre);
}

TEST(system, system_setup)
{
	system_setup();

	/* Should have affinity routing enabled, group 1 interrupts enabled,
	 * group 0 disabled. */
	EXPECT_EQ(io_read32(GICD_CTLR) & 0x13, 0x12);
	EXPECT_EQ(read_msr(ICC_CTLR_EL1) & 0xff, 0);
}

/*
 * Check that an attempt by a secondary VM to access a GICv3 system register is
 * trapped.
 */
TEST(system, icc_ctlr_access_trapped_secondary)
{
	struct ffa_value run_res;

	EXPECT_EQ(ffa_rxtx_map(send_page_addr, recv_page_addr).func,
		  FFA_SUCCESS_32);
	SERVICE_SELECT(SERVICE_VM1, "access_systemreg_ctlr", send_buffer);

	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);
}

/*
 * Check that an attempt by a secondary VM to write ICC_SRE_EL1 is trapped or
 * ignored.
 */
TEST(system, icc_sre_write_trapped_secondary)
{
	struct ffa_value run_res;

	EXPECT_EQ(ffa_rxtx_map(send_page_addr, recv_page_addr).func,
		  FFA_SUCCESS_32);
	SERVICE_SELECT(SERVICE_VM1, "write_systemreg_sre", send_buffer);

	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);
}
