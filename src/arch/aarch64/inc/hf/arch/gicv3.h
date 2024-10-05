/*
 * Copyright 2023 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include <stdint.h>

#include "msr.h"

#define MPIDR_AFFINITY_MASK (0xff00ffffff)
#define MPIDR_AFFLVL_MASK (0xff)
#define MPIDR_AFF0_SHIFT (0)
#define MPIDR_AFF1_SHIFT (8)
#define MPIDR_AFF2_SHIFT (16)
#define MPIDR_AFF3_SHIFT (32)
#define RDIST_AFF3_SHIFT (56)
#define RDIST_AFF2_SHIFT (48)
#define RDIST_AFF1_SHIFT (40)
#define RDIST_AFF0_SHIFT (32)

/* Mask for the configuration field common to all GIC interfaces */
#define GIC_CFG_MASK (0x3)

/* Interrupt configurations: 2-bit fields with LSB reserved */
#define GIC_INTR_CFG_LEVEL (UINT32_C(0) << 1)
#define GIC_INTR_CFG_EDGE (UINT32_C(1) << 1)

/**
 * Common GIC Distributor interface register offsets
 */
#define GICD_CTLR (0x0)
#define GICD_TYPER (0x4)
#define GICD_IIDR (0x8)
#define GICD_IGROUPR (0x80)
#define GICD_ISENABLER (0x100)
#define GICD_ICENABLER (0x180)
#define GICD_ISPENDR (0x200)
#define GICD_ICPENDR (0x280)
#define GICD_ISACTIVER (0x300)
#define GICD_ICACTIVER (0x380)
#define GICD_IPRIORITYR (0x400)
#define GICD_ICFGR (0xc00)
#define GICD_NSACR (0xe00)

/* GICD_CTLR bit definitions */
#define CTLR_ENABLE_G0_SHIFT 0
#define CTLR_ENABLE_G0_MASK (0x1)
#define CTLR_ENABLE_G0_BIT BIT_32(CTLR_ENABLE_G0_SHIFT)

/* Common GIC Distributor interface register constants. */
#define PIDR2_ARCH_REV_SHIFT 4
#define PIDR2_ARCH_REV_MASK 0xf

/* GIC revision as reported by PIDR2.ArchRev register field */
#define ARCH_REV_GICV3 3
#define ARCH_REV_GICV4 4

#define IGROUPR_SHIFT 5
#define ISENABLER_SHIFT 5
#define ICENABLER_SHIFT ISENABLER_SHIFT
#define ISPENDR_SHIFT 5
#define ICPENDR_SHIFT ISPENDR_SHIFT
#define ISACTIVER_SHIFT 5
#define ICACTIVER_SHIFT ISACTIVER_SHIFT
#define IPRIORITYR_SHIFT 2
#define ITARGETSR_SHIFT 2
#define ICFGR_SHIFT 4
#define NSACR_SHIFT 4

#define GIC_PRI_MASK (0xff)

/* Mask non-secure interrupts in Secure World. */
#define SWD_MASK_NS_INT (0x80)

/* Mask all interrupts in Secure World. */
#define SWD_MASK_ALL_INT (0x0)

/**
 * GICv3 and 3.1 specific Distributor interface register offsets and constants
 */
#define GICD_TYPER2 (0x0c)
#define GICD_STATUSR (0x10)
#define GICD_SETSPI_NSR (0x40)
#define GICD_CLRSPI_NSR (0x48)
#define GICD_SETSPI_SR (0x50)
#define GICD_CLRSPI_SR (0x58)
#define GICD_IGRPMODR (0xd00)
#define GICD_IGROUPRE (0x1000)
#define GICD_ISENABLERE (0x1200)
#define GICD_ICENABLERE (0x1400)
#define GICD_ISPENDRE (0x1600)
#define GICD_ICPENDRE (0x1800)
#define GICD_ISACTIVERE (0x1a00)
#define GICD_ICACTIVERE (0x1c00)
#define GICD_IPRIORITYRE (0x2000)
#define GICD_ICFGRE (0x3000)
#define GICD_IGRPMODRE (0x3400)
#define GICD_NSACRE (0x3600)

/**
 * GICD_IROUTER<n> register is at 0x6000 + 8n, where n is the interrupt ID
 * and n >= 32, making the effective offset as 0x6100
 */
#define GICD_IROUTER (0x6000)
#define GICD_IROUTERE (0x8000)

#define GICD_PIDR2_GICV3 (0xffe8)

#define IGRPMODR_SHIFT 5

/* GICD_CTLR bit definitions */
#define CTLR_ENABLE_G1NS_SHIFT 1
#define CTLR_ENABLE_G1S_SHIFT 2
#define CTLR_ARE_S_SHIFT 4
#define CTLR_ARE_NS_SHIFT 5
#define CTLR_DS_SHIFT 6
#define CTLR_E1NWF_SHIFT 7
#define GICD_CTLR_RWP_SHIFT 31

#define CTLR_ENABLE_G1NS_MASK (0x1)
#define CTLR_ENABLE_G1S_MASK (0x1)
#define CTLR_ARE_S_MASK (0x1)
#define CTLR_ARE_NS_MASK (0x1)
#define CTLR_DS_MASK (0x1)
#define CTLR_E1NWF_MASK (0x1)
#define GICD_CTLR_RWP_MASK (0x1)

#define CTLR_ENABLE_G1NS_BIT BIT_32(CTLR_ENABLE_G1NS_SHIFT)
#define CTLR_ENABLE_G1S_BIT BIT_32(CTLR_ENABLE_G1S_SHIFT)
#define CTLR_ARE_S_BIT BIT_32(CTLR_ARE_S_SHIFT)
#define CTLR_ARE_NS_BIT BIT_32(CTLR_ARE_NS_SHIFT)
#define CTLR_DS_BIT BIT_32(CTLR_DS_SHIFT)
#define CTLR_E1NWF_BIT BIT_32(CTLR_E1NWF_SHIFT)
#define GICD_CTLR_RWP_BIT BIT_32(GICD_CTLR_RWP_SHIFT)

/* GICD_IROUTER shifts and masks */
#define IROUTER_SHIFT 0
#define IROUTER_IRM_SHIFT 31
#define IROUTER_IRM_MASK (0x1)

#define GICV3_IRM_PE (0)
#define GICV3_IRM_ANY (1)

#define NUM_OF_DIST_REGS 30

/* GICD_TYPER shifts and masks */
#define TYPER_ESPI (1 << 8)
#define TYPER_SEC_EXTN (1 << 10)
#define TYPER_DVIS (1 << 18)
#define TYPER_ESPI_RANGE_MASK (0x1f)
#define TYPER_ESPI_RANGE_SHIFT (27)
#define TYPER_ESPI_RANGE (TYPER_ESPI_MASK << TYPER_ESPI_SHIFT)

/**
 * Common GIC Redistributor interface registers & constants
 */
#define GICR_SGIBASE_OFFSET (65536) /* 64 KB */
#define GICR_CTLR (0x0)
#define GICR_IIDR (0x04)
#define GICR_TYPER (0x08)
#define GICR_STATUSR (0x10)
#define GICR_WAKER (0x14)
#define GICR_PROPBASER (0x70)
#define GICR_PENDBASER (0x78)
#define GICR_IGROUPR0 (GICR_SGIBASE_OFFSET + (0x80))
#define GICR_ISENABLER0 (GICR_SGIBASE_OFFSET + (0x100))
#define GICR_ICENABLER0 (GICR_SGIBASE_OFFSET + (0x180))
#define GICR_ISPENDR0 (GICR_SGIBASE_OFFSET + (0x200))
#define GICR_ICPENDR0 (GICR_SGIBASE_OFFSET + (0x280))
#define GICR_ISACTIVER0 (GICR_SGIBASE_OFFSET + (0x300))
#define GICR_ICACTIVER0 (GICR_SGIBASE_OFFSET + (0x380))
#define GICR_IPRIORITYR (GICR_SGIBASE_OFFSET + (0x400))
#define GICR_ICFGR0 (GICR_SGIBASE_OFFSET + (0xc00))
#define GICR_ICFGR1 (GICR_SGIBASE_OFFSET + (0xc04))
#define GICR_IGRPMODR0 (GICR_SGIBASE_OFFSET + (0xd00))
#define GICR_NSACR (GICR_SGIBASE_OFFSET + (0xe00))

#define GICR_IGROUPR GICR_IGROUPR0
#define GICR_ISENABLER GICR_ISENABLER0
#define GICR_ICENABLER GICR_ICENABLER0
#define GICR_ISPENDR GICR_ISPENDR0
#define GICR_ICPENDR GICR_ICPENDR0
#define GICR_ISACTIVER GICR_ISACTIVER0
#define GICR_ICACTIVER GICR_ICACTIVER0
#define GICR_ICFGR GICR_ICFGR0
#define GICR_IGRPMODR GICR_IGRPMODR0

/* GICR_CTLR bit definitions */
#define GICR_CTLR_UWP_SHIFT 31
#define GICR_CTLR_UWP_MASK (0x1)
#define GICR_CTLR_UWP_BIT BIT_32(GICR_CTLR_UWP_SHIFT)
#define GICR_CTLR_RWP_SHIFT 3
#define GICR_CTLR_RWP_MASK (0x1)
#define GICR_CTLR_RWP_BIT BIT_32(GICR_CTLR_RWP_SHIFT)
#define GICR_CTLR_EN_LPIS_BIT BIT_32(0)

/**
 * GICv3 and 3.1 CPU interface registers & constants
 */
/* ICC_SRE bit definitions */
#define ICC_SRE_EN_BIT BIT_32(3)
#define ICC_SRE_DIB_BIT BIT_32(2)
#define ICC_SRE_DFB_BIT BIT_32(1)
#define ICC_SRE_SRE_BIT BIT_32(0)

/* ICC_IGRPEN1_EL3 bit definitions */
#define IGRPEN1_EL3_ENABLE_G1NS_SHIFT 0
#define IGRPEN1_EL3_ENABLE_G1S_SHIFT 1

#define IGRPEN1_EL3_ENABLE_G1NS_BIT BIT_32(IGRPEN1_EL3_ENABLE_G1NS_SHIFT)
#define IGRPEN1_EL3_ENABLE_G1S_BIT BIT_32(IGRPEN1_EL3_ENABLE_G1S_SHIFT)

/* ICC_IGRPEN0_EL1 bit definitions */
#define IGRPEN1_EL1_ENABLE_G0_SHIFT 0
#define IGRPEN1_EL1_ENABLE_G0_BIT BIT_32(IGRPEN1_EL1_ENABLE_G0_SHIFT)

/* ICC_HPPIR0_EL1 bit definitions */
#define HPPIR0_EL1_INTID_SHIFT 0
#define HPPIR0_EL1_INTID_MASK (0xffffff)

/* ICC_HPPIR1_EL1 bit definitions */
#define HPPIR1_EL1_INTID_SHIFT 0
#define HPPIR1_EL1_INTID_MASK (0xffffff)

/* ICC_IAR0_EL1 bit definitions */
#define IAR0_EL1_INTID_SHIFT 0
#define IAR0_EL1_INTID_MASK (0xffffff)

/* ICC_IAR1_EL1 bit definitions */
#define IAR1_EL1_INTID_SHIFT 0
#define IAR1_EL1_INTID_MASK (0xffffff)

/* ICC SGI macros */
#define SGIR_TGT_SHIFT 0
#define SGIR_TGT_MASK 0xffff
#define SGIR_AFF1_SHIFT 16
#define SGIR_INTID_SHIFT 24
#define SGIR_INTID_MASK 0xf
#define SGIR_AFF2_SHIFT 32
#define SGIR_IRM_SHIFT 40
#define SGIR_IRM_MASK 0x1
#define SGIR_AFF3_SHIFT 48
#define SGIR_AFF_MASK 0xff

#define SGIR_IRM_TO_AFF (0)

/**
 * GICv3 and 3.1 miscellaneous definitions
 */
/* Interrupt group definitions */
#define INTR_GROUP1S (0)
#define INTR_GROUP0 (1)
#define INTR_GROUP1NS (2)

/* Interrupt IDs reported by the HPPIR and IAR registers */
#define PENDING_G1S_INTID (1020)
#define PENDING_G1NS_INTID (8192)

/* Constant to categorize LPI interrupt */
#define MIN_LPI_ID (8192)

/* GICv3 can only target up to 16 PEs with SGI */
#define GICV3_MAX_SGI_TARGETS (16)

/* PPIs INTIDs 16-31 */
#define MAX_PPI_ID (31)
#define MIN_SPI_ID (32)
#define MAX_SPI_ID (1019)

/**
 * Spurious interrupt ID indicating there are no pending interrupts available
 * to acknowledge in current security state.
 */
#define SPURIOUS_INTID_OTHER_WORLD (1023)

#if GIC_EXT_INTID

/* GICv3.1 extended PPIs INTIDs 1056-1119 */
#define MIN_EPPI_ID (1056)
#define MAX_EPPI_ID (1119)

/* GICv3.1 extended SPIs INTIDs 4096 - 5119 */
#define MIN_ESPI_ID (4096)
#define MAX_ESPI_ID (5119)

/* SGIs: 0-15, PPIs: 16-31, EPPIs: 1056-1119 */
#define IS_SGI_PPI(id)           \
	(((id) <= MAX_PPI_ID) || \
	 (((id) >= MIN_EPPI_ID) && ((id) <= MAX_EPPI_ID)))

/* SPIs: 32-1019, ESPIs: 4096-5119 */
#define IS_SPI(id)                                         \
	((((id) >= MIN_SPI_ID) && ((id) <= MAX_SPI_ID)) || \
	 (((id) >= MIN_ESPI_ID) && ((id) <= MAX_ESPI_ID)))
#else /* GICv3 */
/* SGIs: 0-15, PPIs: 16-31 */
#define IS_SGI_PPI(id) ((id) <= MAX_PPI_ID)

/* SPIs: 32-1019 */
#define IS_SPI(id) (((id) >= MIN_SPI_ID) && ((id) <= MAX_SPI_ID))

#endif /* GIC_EXT_INTID */

/** PPIs associated with various peripheral timers. */
#define ARM_SEL2_TIMER_PHYS_INT UINT32_C(20)
#define ARM_EL1_VIRT_TIMER_PHYS_INT UINT32_C(27)
#define ARM_EL1_PHYS_TIMER_PHYS_INT UINT32_C(30)

static inline uint32_t get_highest_pending_g0_interrupt_id(void)
{
	return (uint32_t)read_msr(ICC_HPPIR0_EL1) & HPPIR0_EL1_INTID_MASK;
}
