/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "../../src/arch/aarch64/hypervisor/perfmon.h"

#include "../../src/arch/aarch64/sysregs.h"
#include "primary_with_secondary.h"
#include "sysregs.h"
#include "test/vmapi/ffa.h"

TEAR_DOWN(perfmon)
{
	EXPECT_FFA_ERROR(ffa_rx_release(), FFA_DENIED);
}

TEST(perfmon, secondary_basic)
{
	struct ffa_value run_res;
	struct mailbox_buffers mb = set_up_mailbox();

	SERVICE_SELECT(SERVICE_VM1, "perfmon_secondary_basic", mb.send);

	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(run_res.func, FFA_YIELD_32);
}

/**
 * Attempts to access performance monitor registers for read, without validating
 * their value.
 */
TEST(perfmon, primary_basic)
{
	EXPECT_EQ(hf_vm_get_id(), HF_PRIMARY_VM_ID);

	TRY_READ(PMCEID0_EL0);
	TRY_READ(PMCEID1_EL0);
	TRY_READ(PMCCFILTR_EL0);
	TRY_READ(PMCR_EL0);
}

/**
 * Tests a few performance counter registers for read and write, and checks that
 * the expected value is written/read.
 */
TEST(perfmon, primary_read_write)
{
	uintreg_t pmcr_el0 = read_msr(PMCR_EL0);
	uintreg_t perf_mon_count = GET_PMCR_EL0_N(pmcr_el0);

	EXPECT_EQ(hf_vm_get_id(), HF_PRIMARY_VM_ID);

	/*
	 * Ensure that there are enough performance counters in the underlying
	 * uArch for this test to pass.
	 */
	EXPECT_GE(perf_mon_count, 4);

	CHECK_UPDATE(PMCCNTR_EL0, 0x5555, 0xaaaa);

	write_msr(PMINTENCLR_EL1, 0xffff);
	CHECK_READ(PMINTENSET_EL1, 0);

	/*
	 * Enable the first and second performance counters.
	 * Bits set in PMINTENSET_EL1 can be read in PMINTENCLR_EL1.
	 */
	write_msr(PMINTENSET_EL1, 0x3);
	CHECK_READ(PMINTENCLR_EL1, 0x3);

	/*
	 * Enable the third and fourth performance counters.
	 * Writes to PMINTENSET_EL1 do not clear already set bits.
	 */
	write_msr(PMINTENSET_EL1, 0xc);
	CHECK_READ(PMINTENCLR_EL1, 0xf);
}

/**
 * Attempts to read all performance counters supported by the current CPU
 * configuration.
 */
/* NOLINTNEXTLINE(readability-function-size) */
TEST(perfmon, primary_counters)
{
	uintreg_t pmcr_el0 = read_msr(PMCR_EL0);
	uintreg_t perf_mon_count = GET_PMCR_EL0_N(pmcr_el0);

	EXPECT_EQ(hf_vm_get_id(), HF_PRIMARY_VM_ID);

	if (perf_mon_count == 0) {
		return;
	}

	switch (perf_mon_count - 1) {
	default:
		FAIL("More performance monitor registers than supported.");
	case 30:
		TRY_READ(PMEVCNTR30_EL0);
		CHECK_UPDATE(PMEVTYPER30_EL0, 0x0, 0x1);
		/* fallthrough */
	case 29:
		TRY_READ(PMEVCNTR29_EL0);
		CHECK_UPDATE(PMEVTYPER29_EL0, 0x0, 0x1);
		/* fallthrough */
	case 28:
		TRY_READ(PMEVCNTR28_EL0);
		CHECK_UPDATE(PMEVTYPER28_EL0, 0x0, 0x1);
		/* fallthrough */
	case 27:
		TRY_READ(PMEVCNTR27_EL0);
		CHECK_UPDATE(PMEVTYPER27_EL0, 0x0, 0x1);
		/* fallthrough */
	case 26:
		TRY_READ(PMEVCNTR26_EL0);
		CHECK_UPDATE(PMEVTYPER26_EL0, 0x0, 0x1);
		/* fallthrough */
	case 25:
		TRY_READ(PMEVCNTR25_EL0);
		CHECK_UPDATE(PMEVTYPER25_EL0, 0x0, 0x1);
		/* fallthrough */
	case 24:
		TRY_READ(PMEVCNTR24_EL0);
		CHECK_UPDATE(PMEVTYPER24_EL0, 0x0, 0x1);
		/* fallthrough */
	case 23:
		TRY_READ(PMEVCNTR23_EL0);
		CHECK_UPDATE(PMEVTYPER23_EL0, 0x0, 0x1);
		/* fallthrough */
	case 22:
		TRY_READ(PMEVCNTR22_EL0);
		CHECK_UPDATE(PMEVTYPER22_EL0, 0x0, 0x1);
		/* fallthrough */
	case 21:
		TRY_READ(PMEVCNTR21_EL0);
		CHECK_UPDATE(PMEVTYPER21_EL0, 0x0, 0x1);
		/* fallthrough */
	case 20:
		TRY_READ(PMEVCNTR20_EL0);
		CHECK_UPDATE(PMEVTYPER20_EL0, 0x0, 0x1);
		/* fallthrough */
	case 19:
		TRY_READ(PMEVCNTR19_EL0);
		CHECK_UPDATE(PMEVTYPER19_EL0, 0x0, 0x1);
		/* fallthrough */
	case 18:
		TRY_READ(PMEVCNTR18_EL0);
		CHECK_UPDATE(PMEVTYPER18_EL0, 0x0, 0x1);
		/* fallthrough */
	case 17:
		TRY_READ(PMEVCNTR17_EL0);
		CHECK_UPDATE(PMEVTYPER17_EL0, 0x0, 0x1);
		/* fallthrough */
	case 16:
		TRY_READ(PMEVCNTR16_EL0);
		CHECK_UPDATE(PMEVTYPER16_EL0, 0x0, 0x1);
		/* fallthrough */
	case 15:
		TRY_READ(PMEVCNTR15_EL0);
		CHECK_UPDATE(PMEVTYPER15_EL0, 0x0, 0x1);
		/* fallthrough */
	case 14:
		TRY_READ(PMEVCNTR14_EL0);
		CHECK_UPDATE(PMEVTYPER14_EL0, 0x0, 0x1);
		/* fallthrough */
	case 13:
		TRY_READ(PMEVCNTR13_EL0);
		CHECK_UPDATE(PMEVTYPER13_EL0, 0x0, 0x1);
		/* fallthrough */
	case 12:
		TRY_READ(PMEVCNTR12_EL0);
		CHECK_UPDATE(PMEVTYPER12_EL0, 0x0, 0x1);
		/* fallthrough */
	case 11:
		TRY_READ(PMEVCNTR11_EL0);
		CHECK_UPDATE(PMEVTYPER11_EL0, 0x0, 0x1);
		/* fallthrough */
	case 10:
		TRY_READ(PMEVCNTR10_EL0);
		CHECK_UPDATE(PMEVTYPER10_EL0, 0x0, 0x1);
		/* fallthrough */
	case 9:
		TRY_READ(PMEVCNTR9_EL0);
		CHECK_UPDATE(PMEVTYPER9_EL0, 0x0, 0x1);
		/* fallthrough */
	case 8:
		TRY_READ(PMEVCNTR8_EL0);
		CHECK_UPDATE(PMEVTYPER8_EL0, 0x0, 0x1);
		/* fallthrough */
	case 7:
		TRY_READ(PMEVCNTR7_EL0);
		CHECK_UPDATE(PMEVTYPER7_EL0, 0x0, 0x1);
		/* fallthrough */
	case 6:
		TRY_READ(PMEVCNTR6_EL0);
		CHECK_UPDATE(PMEVTYPER6_EL0, 0x0, 0x1);
		/* fallthrough */
	case 5:
		TRY_READ(PMEVCNTR5_EL0);
		CHECK_UPDATE(PMEVTYPER5_EL0, 0x0, 0x1);
		/* fallthrough */
	case 4:
		TRY_READ(PMEVCNTR4_EL0);
		CHECK_UPDATE(PMEVTYPER4_EL0, 0x0, 0x1);
		/* fallthrough */
	case 3:
		TRY_READ(PMEVCNTR3_EL0);
		CHECK_UPDATE(PMEVTYPER3_EL0, 0x0, 0x1);
		/* fallthrough */
	case 2:
		TRY_READ(PMEVCNTR2_EL0);
		CHECK_UPDATE(PMEVTYPER2_EL0, 0x0, 0x1);
		/* fallthrough */
	case 1:
		TRY_READ(PMEVCNTR1_EL0);
		CHECK_UPDATE(PMEVTYPER1_EL0, 0x0, 0x1);
		/* fallthrough */
	case 0:
		TRY_READ(PMEVCNTR0_EL0);
		CHECK_UPDATE(PMEVTYPER0_EL0, 0x0, 0x1);
		break;
	}
}
