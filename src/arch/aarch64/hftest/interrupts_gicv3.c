/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/vm/interrupts_gicv3.h"

#include <stdbool.h>
#include <stdint.h>

#include "hf/cpu.h"
#include "hf/dlog.h"

#include "msr.h"

/*
 * These values for calculating the address of the redistributor are specific
 * to FVP. If required they can be moved to platform specific headers to be
 * changed according to the platform at compile time.
 */
#define GICV3_REDIST_SIZE_PER_PE UINT64_C(128 * 1024) /* 128 KB */
#define FVP_CLUSTER_MPIDR_INCREMENT UINT64_C(0x10000)
#define FVP_CPU_MPIDR_INCREMENT UINT64_C(0x100)
#define FVP_CLUSTER_SIZE UINT64_C(4)

/*
 * Return the address of the redistributor for the current core.
 * NOTE the calculation is specific to the FVP platform.
 */
uint64_t interrupt_get_gic_rdist_addr(void)
{
	uint32_t mpidr = read_msr(MPIDR_EL1) & 0xff00ffffff;
	size_t cpu_idx =
		((mpidr % FVP_CLUSTER_MPIDR_INCREMENT) /
		 FVP_CPU_MPIDR_INCREMENT) +
		((FVP_CLUSTER_SIZE * mpidr) / FVP_CLUSTER_MPIDR_INCREMENT);

	return GICR_BASE + (cpu_idx * GICV3_REDIST_SIZE_PER_PE);
}

/**
 * This function checks the interrupt ID and returns true for SGIs and PPIs.
 */
bool is_ppi_sgi(uint32_t id)
{
	/* SGIs: 0-15, PPIs: 16-31. */
	if (id <= MAX_PPI_ID) {
		return true;
	}

	return false;
}

void interrupt_gic_setup(void)
{
	uint32_t ctlr = 1U << 4	   /* Enable affinity routing. */
			| 1U << 1; /* Enable group 1 non-secure interrupts. */
	uint64_t rdist_addr = interrupt_get_gic_rdist_addr();
	io32_t gicr_waker = IO32_C(rdist_addr + GICR_WAKER);
	io32_t gicr_igroupr0 = IO32_C(rdist_addr + GICR_IGROUPR0);

	write_msr(ICC_CTLR_EL1, 0);

	io_write32(GICD_CTLR, ctlr);

	/* Mark CPU as awake. */
	io_write32(gicr_waker, io_read32(gicr_waker) & ~(1U << 1));
	while ((io_read32(gicr_waker) & (1U << 2)) != 0) {
		dlog_info("Waiting for ChildrenAsleep==0\n");
	}

	/* Put interrupts into non-secure group 1. */
	dlog_info("GICR_IGROUPR0 was %x\n", io_read32(gicr_igroupr0));
	io_write32(gicr_igroupr0, 0xffffffff);
	dlog_info("wrote %x to GICR_IGROUPR0, got back %x\n", 0xffffffff,
		  io_read32(gicr_igroupr0));
	/* Enable non-secure group 1. */
	write_msr(ICC_IGRPEN1_EL1, 0x00000001);
	dlog_info("wrote %x to ICC_IGRPEN1_EL1, got back %lx\n", 0x00000001,
		  read_msr(ICC_IGRPEN1_EL1));
}

void interrupt_enable(uint32_t intid, bool enable)
{
	uint32_t index = intid / 32;
	uint32_t bit = 1U << (intid % 32);
	uint64_t rdist_addr = interrupt_get_gic_rdist_addr();
	io32_t gicr_isenabler0 = IO32_C(rdist_addr + GICR_ISENABLER0);
	io32_t gicr_icenabler0 = IO32_C(rdist_addr + GICR_ICENABLER0);

	if (enable) {
		io_write32_array(GICD_ISENABLER, index, bit);
		if (is_ppi_sgi(intid)) {
			io_write32(gicr_isenabler0, bit);
		}
	} else {
		io_write32_array(GICD_ICENABLER, index, bit);
		if (is_ppi_sgi(intid)) {
			io_write32(gicr_icenabler0, bit);
		}
	}
}

void interrupt_enable_all(bool enable)
{
	uint32_t i;
	uint64_t rdist_addr = interrupt_get_gic_rdist_addr();
	io32_t gicr_isenabler0 = IO32_C(rdist_addr + GICR_ISENABLER0);

	if (enable) {
		io_write32(gicr_isenabler0, 0xffffffff);
		for (i = 0; i < 32; ++i) {
			io_write32_array(GICD_ISENABLER, i, 0xffffffff);
		}
	} else {
		io_write32(gicr_isenabler0, 0);
		for (i = 0; i < 32; ++i) {
			io_write32_array(GICD_ISENABLER, i, 0);
		}
	}
}

void interrupt_set_priority_mask(uint8_t min_priority)
{
	write_msr(ICC_PMR_EL1, min_priority);
}

void interrupt_set_priority(uint32_t intid, uint8_t priority)
{
	uint64_t rdist_addr = interrupt_get_gic_rdist_addr();

	if (is_ppi_sgi(intid)) {
		io_write8_array(IO8_ARRAY_C(rdist_addr + GICR_IPRIORITYR, 32),
				intid, priority & GIC_PRI_MASK);
	} else {
		io_write8_array(GICD_IPRIORITYR, intid,
				priority & GIC_PRI_MASK);
	}
}

void interrupt_set_edge_triggered(uint32_t intid, bool edge_triggered)
{
	uint32_t index = intid / 16;
	uint32_t bit = 1U << (((intid % 16) * 2) + 1);
	uint64_t rdist_addr = interrupt_get_gic_rdist_addr();
	io32_array_t gicr_icfgr = IO32_ARRAY_C(rdist_addr + GICR_ICFGR, 32);

	if (is_ppi_sgi(intid)) {
		uint32_t v = io_read32_array(gicr_icfgr, index);

		if (edge_triggered) {
			io_write32_array(gicr_icfgr, index, v | bit);
		} else {
			io_write32_array(gicr_icfgr, index, v & ~bit);
		}
	} else {
		uint32_t v = io_read32_array(GICD_ICFGR, index);

		if (edge_triggered) {
			io_write32_array(GICD_ICFGR, index, v | bit);
		} else {
			io_write32_array(GICD_ICFGR, index, v & ~bit);
		}
	}
}

void interrupt_send_sgi(uint8_t intid, bool irm, uint8_t affinity3,
			uint8_t affinity2, uint8_t affinity1,
			uint16_t target_list)
{
	uint64_t sgi_register =
		((uint64_t)target_list) | ((uint64_t)affinity1 << 16) |
		(((uint64_t)intid & 0x0f) << 24) | ((uint64_t)affinity2 << 32) |
		((uint64_t)irm << 40) | ((uint64_t)affinity3 << 48);

	write_msr(ICC_SGI1R_EL1, sgi_register);
}

uint32_t interrupt_get_and_acknowledge(void)
{
	return read_msr(ICC_IAR1_EL1);
}

void interrupt_end(uint32_t intid)
{
	write_msr(ICC_EOIR1_EL1, intid);
}
