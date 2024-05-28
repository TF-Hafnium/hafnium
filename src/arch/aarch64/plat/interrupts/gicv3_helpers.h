/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/gicv3.h"

#include "hf/cpu.h"
#include "hf/dlog.h"
#include "hf/io.h"
#include "hf/panic.h"
#include "hf/plat/interrupts.h"
#include "hf/static_assert.h"
#include "hf/types.h"

#define BIT_32(nr) (UINT32_C(1) << (nr))

/**
 * GICv3 private macro definitions
 */

/* Constants to indicate the status of the RWP bit */
#define RWP_TRUE (1)
#define RWP_FALSE (0)

/* Calculate GIC register bit number corresponding to its interrupt ID */
#define BIT_NUM(REG, id) ((id) & ((1U << REG##R_SHIFT) - 1U))

/*
 * Calculate 8, 32 and 64-bit GICD register offset
 * corresponding to its interrupt ID
 */
#if GIC_EXT_INTID
/* GICv3.1 */
#define GICD_OFFSET_8(REG, id)                     \
	(((id) <= MAX_SPI_ID)                      \
		 ? GICD_##REG##R + (uintptr_t)(id) \
		 : GICD_##REG##RE + (uintptr_t)(id) - MIN_ESPI_ID)

#define GICD_OFFSET(REG, id)                                                  \
	(((id) <= MAX_SPI_ID)                                                 \
		 ? GICD_##REG##R + (((uintptr_t)(id) >> REG##R_SHIFT) << 2)   \
		 : GICD_##REG##RE +                                           \
			   ((((uintptr_t)(id) - MIN_ESPI_ID) >> REG##R_SHIFT) \
			    << 2))

#define GICD_OFFSET_64(REG, id)                                               \
	(((id) <= MAX_SPI_ID)                                                 \
		 ? GICD_##REG##R + (((uintptr_t)(id) >> REG##R_SHIFT) << 3)   \
		 : GICD_##REG##RE +                                           \
			   ((((uintptr_t)(id) - MIN_ESPI_ID) >> REG##R_SHIFT) \
			    << 3))

#else /* GICv3 */
#define GICD_OFFSET_8(REG, id) (GICD_##REG##R + (uintptr_t)(id))

#define GICD_OFFSET(REG, id) \
	(GICD_##REG##R + (((uintptr_t)(id) >> REG##R_SHIFT) << 2))

#define GICD_OFFSET_64(REG, id) \
	(GICD_##REG##R + (((uintptr_t)(id) >> REG##R_SHIFT) << 3))
#endif /* GIC_EXT_INTID */

/*
 * Read/Write 8, 32 and 64-bit GIC Distributor register
 * corresponding to its interrupt ID
 */
#define GICD_READ(REG, base, id) \
	io_read32(IO32_C((base) + GICD_OFFSET(REG, (id))))

#define GICD_READ_64(REG, base, id) \
	io_read64(IO64_C((base) + GICD_OFFSET_64(REG, (id))))

#define GICD_WRITE_8(REG, base, id, val) \
	io_write8(IO8_C((base) + GICD_OFFSET_8(REG, (id))), (val))

#define GICD_WRITE(REG, base, id, val) \
	io_write32(IO32_C((base) + GICD_OFFSET(REG, (id)), (val)))

#define GICD_WRITE_64(REG, base, id, val) \
	io_write64(IO64_C((base) + GICD_OFFSET_64(REG, (id))), (val))

/*
 * Bit operations on GIC Distributor register corresponding
 * to its interrupt ID
 */
/* Get bit in GIC Distributor register */
#define GICD_GET_BIT(REG, base, id)                             \
	((io_read32(IO32_C((base) + GICD_OFFSET(REG, (id)))) >> \
	  BIT_NUM(REG, (id))) &                                 \
	 1U)

/* Set bit in GIC Distributor register */
#define GICD_SET_BIT(REG, base, id)                           \
	io_setbits32(IO32_C((base) + GICD_OFFSET(REG, (id))), \
		     ((uint32_t)1 << BIT_NUM(REG, (id))))

/* Clear bit in GIC Distributor register */
#define GICD_CLR_BIT(REG, base, id)                           \
	io_clrbits32(IO32_C((base) + GICD_OFFSET(REG, (id))), \
		     ((uint32_t)1 << BIT_NUM(REG, (id))))

/* Write bit in GIC Distributor register */
#define GICD_WRITE_BIT(REG, base, id)                       \
	io_write32(IO32_C((base) + GICD_OFFSET(REG, (id))), \
		   ((uint32_t)1 << BIT_NUM(REG, (id))))

/*
 * Calculate 8 and 32-bit GICR register offset
 * corresponding to its interrupt ID
 */
#if GIC_EXT_INTID
/* GICv3.1 */
#define GICR_OFFSET_8(REG, id)                                    \
	(((id) <= MAX_PPI_ID) ? GICR_##REG##R + (uintptr_t)(id)   \
			      : GICR_##REG##R + (uintptr_t)(id) - \
					(MIN_EPPI_ID - MIN_SPI_ID))

#define GICR_OFFSET(REG, id)                                                   \
	(((id) <= MAX_PPI_ID)                                                  \
		 ? GICR_##REG##R + (((uintptr_t)(id) >> REG##R_SHIFT) << 2)    \
		 : GICR_##REG##R +                                             \
			   ((((uintptr_t)(id) - (MIN_EPPI_ID - MIN_SPI_ID)) >> \
			     REG##R_SHIFT)                                     \
			    << 2))
#else /* GICv3 */
#define GICR_OFFSET_8(REG, id) (GICR_##REG##R + (uintptr_t)(id))

#define GICR_OFFSET(REG, id) \
	(GICR_##REG##R + (((uintptr_t)(id) >> REG##R_SHIFT) << 2))
#endif /* GIC_EXT_INTID */

/* Read/Write GIC Redistributor register corresponding to its interrupt ID */
#define GICR_READ(REG, base, id) \
	io_read32(IO32_C((base) + GICR_OFFSET(REG, (id))))

#define GICR_WRITE_8(REG, base, id, val) \
	io_write8(IO8_C((base) + GICR_OFFSET_8(REG, (id))), (val))

#define GICR_WRITE(REG, base, id, val) \
	io_write32(IO32_C((base) + GICR_OFFSET(REG, (id))), (val))

/*
 * Bit operations on GIC Redistributor register
 * corresponding to its interrupt ID
 */

/* Get bit in GIC Redistributor register */
#define GICR_GET_BIT(REG, base, id)                             \
	((io_read32(IO32_C((base) + GICR_OFFSET(REG, (id)))) >> \
	  BIT_NUM(REG, (id))) &                                 \
	 1U)

/* Write bit in GIC Redistributor register */
#define GICR_WRITE_BIT(REG, base, id)                       \
	io_write32(IO32_C((base) + GICR_OFFSET(REG, (id))), \
		   ((uint32_t)1 << BIT_NUM(REG, (id))))

/* Set bit in GIC Redistributor register */
#define GICR_SET_BIT(REG, base, id)                           \
	io_setbits32(IO32_C((base) + GICR_OFFSET(REG, (id))), \
		     ((uint32_t)1 << BIT_NUM(REG, (id))))

/* Clear bit in GIC Redistributor register */
#define GICR_CLR_BIT(REG, base, id)                           \
	io_clrbits32(IO32_C((base) + GICR_OFFSET(REG, (id))), \
		     ((uint32_t)1 << BIT_NUM(REG, (id))))

static inline uint64_t gicd_irouter_val_from_mpidr(uint64_t mpidr,
						   unsigned int irm)
{
	return (mpidr & ~(UINT32_C(0xff) << 24)) |
	       ((irm & IROUTER_IRM_MASK) << IROUTER_IRM_SHIFT);
}

/**
 * GIC Distributor interface register accessors
 */
static inline unsigned int gicd_read_ctlr(uintptr_t base)
{
	return io_read32(IO32_C(base + GICD_CTLR));
}

static inline void gicd_write_ctlr(uintptr_t base, unsigned int val)
{
	io_write32(IO32_C(base + GICD_CTLR), val);
}

/**
 * GIC Distributor interface accessors
 */
static inline void gicd_wait_for_pending_write(uintptr_t gicd_base)
{
	while ((gicd_read_ctlr(gicd_base) & GICD_CTLR_RWP_BIT) != 0U) {
	}
}

static inline uint32_t gicd_read_pidr2(uintptr_t base)
{
	return io_read32(IO32_C(base + GICD_PIDR2_GICV3));
}

static inline void gicd_write_irouter(uintptr_t base, unsigned int id,
				      uint64_t affinity)
{
	CHECK(id >= MIN_SPI_ID);
	GICD_WRITE_64(IROUTE, base, id, affinity);
}

/*
 * Any function that intends to update the following fields of GICD_CTLR
 * memory mapped register must prefer gicd_set_ctlr() helper over
 * gicd_write_ctlr().
 * 1. GICD_CTLR[2:0] - the Group Enables
 * 2. GICD_CTLR[7:4] - the ARE bits, E1NWF bit and DS bit
 * 3. GICD_ICENABLER<n> - the clearing of enable state for SPIs
 */
static inline void gicd_set_ctlr(uintptr_t base, uint32_t bitmap, uint32_t rwp)
{
	gicd_write_ctlr(base, gicd_read_ctlr(base) | bitmap);

	if (rwp != RWP_FALSE) {
		gicd_wait_for_pending_write(base);
	}
}

/**
 * GIC Redistributor interface accessors
 */
static inline uint32_t gicr_read_ctlr(uintptr_t base)
{
	return io_read32(IO32_C(base + GICR_CTLR));
}

/*
 * Wait for updates to:
 * GICR_ICENABLER0
 * GICR_CTLR.DPG1S
 * GICR_CTLR.DPG1NS
 * GICR_CTLR.DPG0
 * GICR_CTLR, which clears EnableLPIs from 1 to 0
 */
static inline void gicr_wait_for_pending_write(uintptr_t gicr_base)
{
	while ((gicr_read_ctlr(gicr_base) & GICR_CTLR_RWP_BIT) != 0U) {
	}
}

/**
 * GIC Distributor functions for accessing the GIC registers
 * corresponding to a single interrupt ID. These functions use bitwise
 * operations or appropriate register accesses to modify or return
 * the bit-field corresponding the single interrupt ID.
 */

/**
 * Accessors to set the bits corresponding to interrupt ID
 * in GIC Distributor ICFGR and ICFGRE.
 */
void gicd_set_icfgr(uintptr_t base, unsigned int id, unsigned int cfg)
{
	/* Interrupt configuration is a 2-bit field */
	unsigned int bit_shift = BIT_NUM(ICFG, id) << 1U;

	/* Clear the field, and insert required configuration */
	io_clrsetbits32(IO32_C(base + GICD_OFFSET(ICFG, id)),
			(uint32_t)GIC_CFG_MASK << bit_shift,
			(cfg & GIC_CFG_MASK) << bit_shift);
}

/**
 * Accessors to get/set/clear the bit corresponding to interrupt ID
 * in GIC Distributor IGROUPR and IGROUPRE.
 */
unsigned int gicd_get_igroupr(uintptr_t base, unsigned int id)
{
	return GICD_GET_BIT(IGROUP, base, id);
}

void gicd_set_igroupr(uintptr_t base, unsigned int id)
{
	GICD_SET_BIT(IGROUP, base, id);
}

void gicd_clr_igroupr(uintptr_t base, unsigned int id)
{
	GICD_CLR_BIT(IGROUP, base, id);
}

/**
 * Accessors to get/set/clear the bit corresponding to interrupt ID
 * in GIC Distributor IGRPMODR and IGRPMODRE.
 */
unsigned int gicd_get_igrpmodr(uintptr_t base, unsigned int id)
{
	return GICD_GET_BIT(IGRPMOD, base, id);
}

void gicd_set_igrpmodr(uintptr_t base, unsigned int id)
{
	GICD_SET_BIT(IGRPMOD, base, id);
}

void gicd_clr_igrpmodr(uintptr_t base, unsigned int id)
{
	GICD_CLR_BIT(IGRPMOD, base, id);
}

/**
 * Accessors to set the bit corresponding to interrupt ID
 * in GIC Distributor ICENABLER and ICENABLERE.
 */
void gicd_set_icenabler(uintptr_t base, unsigned int id)
{
	GICD_WRITE_BIT(ICENABLE, base, id);
}

/**
 * Accessors to set the bit corresponding to interrupt ID
 * in GIC Distributor ISENABLER and ISENABLERE.
 */
void gicd_set_isenabler(uintptr_t base, unsigned int id)
{
	GICD_WRITE_BIT(ISENABLE, base, id);
}

/**
 * Accessors to set the bit corresponding to interrupt ID
 * in GIC Distributor IPRIORITYR and IPRIORITYRE.
 */
void gicd_set_ipriorityr(uintptr_t base, unsigned int id, unsigned int pri)
{
	GICD_WRITE_8(IPRIORITY, base, id, (uint8_t)(pri & GIC_PRI_MASK));
}

/**
 * Accessor to set the byte corresponding to interrupt `id`
 * in GIC Redistributor IPRIORITYR and IPRIORITYRE.
 */
void gicr_set_ipriorityr(uintptr_t base, unsigned int id, unsigned int pri)
{
	GICR_WRITE_8(IPRIORITY, base, id, (uint8_t)(pri & GIC_PRI_MASK));
}

/**
 * Accessors to get/set/clear the bit corresponding to interrupt `id`
 * from GIC Redistributor IGROUPR0 and IGROUPRE
 */
unsigned int gicr_get_igroupr(uintptr_t base, unsigned int id)
{
	return GICR_GET_BIT(IGROUP, base, id);
}

void gicr_set_igroupr(uintptr_t base, unsigned int id)
{
	GICR_SET_BIT(IGROUP, base, id);
}

void gicr_clr_igroupr(uintptr_t base, unsigned int id)
{
	GICR_CLR_BIT(IGROUP, base, id);
}

/**
 * Accessors to get/set/clear the bit corresponding to interrupt `id`
 * from GIC Redistributor IGRPMODR0 and IGRPMODRE
 */
unsigned int gicr_get_igrpmodr(uintptr_t base, unsigned int id)
{
	return GICR_GET_BIT(IGRPMOD, base, id);
}

void gicr_set_igrpmodr(uintptr_t base, unsigned int id)
{
	GICR_SET_BIT(IGRPMOD, base, id);
}

void gicr_clr_igrpmodr(uintptr_t base, unsigned int id)
{
	GICR_CLR_BIT(IGRPMOD, base, id);
}

/**
 * Accessor to write the bit corresponding to interrupt `id`
 * in GIC Redistributor ISENABLER0 and ISENABLERE
 */
void gicr_set_isenabler(uintptr_t base, unsigned int id)
{
	GICR_WRITE_BIT(ISENABLE, base, id);
}

/**
 * Accessor to write the bit corresponding to interrupt `id`
 * in GIC Redistributor ICENABLER0 and ICENABLERE
 */
void gicr_set_icenabler(uintptr_t base, unsigned int id)
{
	GICR_WRITE_BIT(ICENABLE, base, id);
}

/**
 * Accessor to set the bit fields corresponding to interrupt `id`
 * in GIC Redistributor ICFGR0, ICFGR1 and ICFGRE
 */
void gicr_set_icfgr(uintptr_t base, unsigned int id, unsigned int cfg)
{
	/* Interrupt configuration is a 2-bit field */
	unsigned int bit_shift = BIT_NUM(ICFG, id) << 1U;

	/* Clear the field, and insert required configuration */
	io_clrsetbits32(IO32_C(base + GICR_OFFSET(ICFG, id)),
			(uint32_t)GIC_CFG_MASK << bit_shift,
			(cfg & GIC_CFG_MASK) << bit_shift);
}
