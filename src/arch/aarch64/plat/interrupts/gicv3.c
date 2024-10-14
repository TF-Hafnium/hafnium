/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include <libfdt.h>

#include "hf/check.h"
#include "hf/cpu.h"
#include "hf/dlog.h"
#include "hf/interrupt_desc.h"
#include "hf/io.h"
#include "hf/panic.h"
#include "hf/plat/interrupts.h"
#include "hf/static_assert.h"
#include "hf/types.h"

#include "gicv3_helpers.h"
#include "msr.h"

#define MAX_CHIPS 16

#define GICD_SIZE (0x10000)

/**
 * In GICv3, each Redistributor has two 64KB frames:
 * 1. RD_base
 * 2. SGI_base
 */
#define GICV3_REDIST_SIZE_PER_PE (0x20000) /* 128 KB */

/**
 * In GICv4, each Redistributor has two additional 64KB frames:
 * 3. VLPI_base
 * 4. Reserved
 */
#define GICV4_REDIST_SIZE_PER_PE (0x40000) /* 256 KB */

#if GIC_VERSION == 3
#define GIC_REDIST_SIZE_PER_PE GICV3_REDIST_SIZE_PER_PE
#elif GIC_VERSION == 4
#define GIC_REDIST_SIZE_PER_PE GICV4_REDIST_SIZE_PER_PE
#endif

#define GIC_REDIST_FRAMES_OFFSET GIC_REDIST_SIZE_PER_PE
#define REDIST_LAST_FRAME_MASK (1 << 4)

struct gicv3_driver {
	uintptr_t dist_base;
	uintptr_t all_redist_frames[MAX_CPUS];
	struct spinlock lock;
};

static struct gicv3_driver plat_gicv3_driver;

/**
 * This function checks the interrupt ID and returns true for SGIs and (E)PPIs
 * and false for (E)SPIs IDs.
 */
static bool is_sgi_ppi(uint32_t id)
{
	/* SGIs: 0-15, PPIs: 16-31, EPPIs: 1056-1119. */
	if (IS_SGI_PPI(id)) {
		return true;
	}

	/* SPIs: 32-1019, ESPIs: 4096-5119. */
	if (IS_SPI(id)) {
		return false;
	}

	CHECK(false);
	return false;
}

/**
 * This function returns the id of the highest priority pending interrupt at
 * the GIC cpu interface.
 */
uint32_t gicv3_get_pending_interrupt_id(void)
{
	return (uint32_t)read_msr(ICC_IAR1_EL1) & IAR1_EL1_INTID_MASK;
}

/**
 * This function returns the type of the interrupt id depending on the group
 * this interrupt has been configured under by the interrupt controller i.e.
 * group0 or group1 Secure / Non Secure. The return value can be one of the
 * following :
 *    INTR_GROUP0  : The interrupt type is a Secure Group 0 interrupt
 *    INTR_GROUP1S : The interrupt type is a Secure Group 1 secure interrupt.
 *    INTR_GROUP1NS: The interrupt type is a Secure Group 1 non secure
 *                   interrupt.
 */
uint32_t gicv3_get_interrupt_type(uint32_t id, uint32_t proc_num)
{
	uint32_t igroup;
	uint32_t grpmodr;
	uintptr_t gicr_base;

	/* Ensure the parameters are valid. */
	CHECK((id < PENDING_G1S_INTID) || (id >= MIN_LPI_ID));
	CHECK(proc_num < MAX_CPUS);

	/* All LPI interrupts are Group 1 non secure. */
	if (id >= MIN_LPI_ID) {
		return INTR_GROUP1NS;
	}

	/* Check interrupt ID. */
	if (is_sgi_ppi(id)) {
		/* SGIs: 0-15, PPIs: 16-31, EPPIs: 1056-1119. */
		gicr_base = plat_gicv3_driver.all_redist_frames[proc_num];
		igroup = gicr_get_igroupr(gicr_base, id);
		grpmodr = gicr_get_igrpmodr(gicr_base, id);
	} else {
		/* SPIs: 32-1019, ESPIs: 4096-5119. */
		igroup = gicd_get_igroupr(plat_gicv3_driver.dist_base, id);
		grpmodr = gicd_get_igrpmodr(plat_gicv3_driver.dist_base, id);
	}

	/*
	 * If the IGROUP bit is set, then it is a Group 1 Non secure
	 * interrupt.
	 */
	if (igroup != 0U) {
		return INTR_GROUP1NS;
	}

	/* If the GRPMOD bit is set, then it is a Group 1 Secure interrupt. */
	if (grpmodr != 0U) {
		return INTR_GROUP1S;
	}

	CHECK(false);

	/* Else it is a Group 0 Secure interrupt */
	return INTR_GROUP0;
}

/**
 * This function enables the interrupt identified by id. The proc_num
 * is used if the interrupt is SGI or PPI, and programs the corresponding
 * Redistributor interface.
 */
void gicv3_enable_interrupt(uint32_t id, uint32_t proc_num)
{
	CHECK(plat_gicv3_driver.dist_base != 0U);
	CHECK(plat_gicv3_driver.all_redist_frames[proc_num] != 0U);
	CHECK(proc_num < MAX_CPUS);

	/*
	 * Ensure that any shared variable updates depending on out of band
	 * interrupt trigger are observed before enabling interrupt.
	 */
	dsb(ish);

	/* Check interrupt ID. */
	if (is_sgi_ppi(id)) {
		/* For SGIs: 0-15, PPIs: 16-31 and EPPIs: 1056-1119. */
		gicr_set_isenabler(
			plat_gicv3_driver.all_redist_frames[proc_num], id);
	} else {
		/* For SPIs: 32-1019 and ESPIs: 4096-5119. */
		gicd_set_isenabler(plat_gicv3_driver.dist_base, id);
	}
}

/**
 * This function disables the interrupt identified by id. The proc_num
 * is used if the interrupt is SGI or PPI, and programs the corresponding
 * Redistributor interface.
 */
void gicv3_disable_interrupt(uint32_t id, uint32_t proc_num)
{
	CHECK(plat_gicv3_driver.dist_base != 0U);
	CHECK(plat_gicv3_driver.all_redist_frames[proc_num] != 0U);
	CHECK(proc_num < MAX_CPUS);

	/*
	 * Disable interrupt, and ensure that any shared variable updates
	 * depending on out of band interrupt trigger are observed afterwards.
	 */

	/* Check interrupt ID. */
	if (is_sgi_ppi(id)) {
		/* For SGIs: 0-15, PPIs: 16-31 and EPPIs: 1056-1119. */
		gicr_set_icenabler(
			plat_gicv3_driver.all_redist_frames[proc_num], id);

		/* Write to clear enable requires waiting for pending writes. */
		gicr_wait_for_pending_write(
			plat_gicv3_driver.all_redist_frames[proc_num]);
	} else {
		/* For SPIs: 32-1019 and ESPIs: 4096-5119. */
		gicd_set_icenabler(plat_gicv3_driver.dist_base, id);

		/* Write to clear enable requires waiting for pending writes. */
		gicd_wait_for_pending_write(plat_gicv3_driver.dist_base);
	}

	dsb(ish);
}

/**
 * This function sets the interrupt priority as supplied for the given interrupt
 * id.
 */
void gicv3_set_interrupt_priority(uint32_t id, uint32_t core_pos,
				  uint32_t priority)
{
	uintptr_t gicr_base;

	/* Core index cannot exceed maximum core count. */
	CHECK(core_pos < MAX_CPUS);

	/* Check interrupt ID. */
	if (is_sgi_ppi(id)) {
		/* For SGIs: 0-15, PPIs: 16-31 and EPPIs: 1056-1119. */
		gicr_base = plat_gicv3_driver.all_redist_frames[core_pos];
		gicr_set_ipriorityr(gicr_base, id, priority);
	} else {
		/* For SPIs: 32-1019 and ESPIs: 4096-5119. */
		gicd_set_ipriorityr(plat_gicv3_driver.dist_base, id, priority);
	}
}

/**
 * This function assigns group for the interrupt identified by id. The proc_num
 * is used if the interrupt is SGI or (E)PPI, and programs the corresponding
 * Redistributor interface. The group can be any of GICV3_INTR_GROUP*.
 */
void gicv3_set_interrupt_type(uint32_t id, uint32_t proc_num, uint32_t type)
{
	bool igroup = false;
	bool grpmod = false;
	uintptr_t gicr_base;

	CHECK(plat_gicv3_driver.dist_base != 0U);
	CHECK(proc_num < MAX_CPUS);

	switch (type) {
	case INTR_GROUP1S:
		igroup = false;
		grpmod = true;
		break;
	case INTR_GROUP1NS:
		igroup = true;
		grpmod = false;
		break;
	default:
		CHECK(false);
		break;
	}

	/* Check interrupt ID. */
	if (is_sgi_ppi(id)) {
		/* For SGIs: 0-15, PPIs: 16-31 and EPPIs: 1056-1119. */
		gicr_base = plat_gicv3_driver.all_redist_frames[proc_num];

		igroup ? gicr_set_igroupr(gicr_base, id)
		       : gicr_clr_igroupr(gicr_base, id);
		grpmod ? gicr_set_igrpmodr(gicr_base, id)
		       : gicr_clr_igrpmodr(gicr_base, id);
	} else {
		/* For SPIs: 32-1019 and ESPIs: 4096-5119. */

		/* Serialize read-modify-write to Distributor registers. */
		sl_lock(&plat_gicv3_driver.lock);

		igroup ? gicd_set_igroupr(plat_gicv3_driver.dist_base, id)
		       : gicd_clr_igroupr(plat_gicv3_driver.dist_base, id);
		grpmod ? gicd_set_igrpmodr(plat_gicv3_driver.dist_base, id)
		       : gicd_clr_igrpmodr(plat_gicv3_driver.dist_base, id);

		sl_unlock(&plat_gicv3_driver.lock);
	}
}

void gicv3_end_of_interrupt(uint32_t id)
{
	/*
	 * Interrupt request deassertion from peripheral to GIC happens
	 * by clearing interrupt condition by a write to the peripheral
	 * register. It is desired that the write transfer is complete
	 * before the core tries to change GIC state from 'AP/Active' to
	 * a new state on seeing 'EOI write'.
	 * Since ICC interface writes are not ordered against Device
	 * memory writes, a barrier is required to ensure the ordering.
	 * The dsb will also ensure *completion* of previous writes with
	 * DEVICE nGnRnE attribute.
	 */
	dsb(ish);
	write_msr(ICC_EOIR1_EL1, id);
}

/**
 * A copy from libfdt. Dependency of `fdt_redistributor_regions_cells`
 */
static int fdt_cells(const void *fdt, int nodeoffset, const char *name)
{
	const fdt32_t *c;
	uint32_t val;
	int len;

	c = fdt_getprop(fdt, nodeoffset, name, &len);
	if (!c) {
		return len;
	}
	if (len != sizeof(*c)) {
		return -FDT_ERR_BADNCELLS;
	}
	val = fdt32_to_cpu(*c);
	if (val > FDT_MAX_NCELLS) {
		return -FDT_ERR_BADNCELLS;
	}
	return (int)val;
}

static int fdt_redistributor_regions_cells(const void *fdt, int nodeoffset)
{
	int val;

	val = fdt_cells(fdt, nodeoffset, "#redistributor-regions");
	if (val == -FDT_ERR_NOTFOUND) {
		return 1;
	}
	return val;
}

/**
 * Retrieves redistributor count for a bus represented in the device tree.
 * Result is value of '#redistributor-regions' at `node`.
 * If '#redistributor-regions' is not found, the default value is 1 cell.
 * Returns true on success, false if an error occurred.
 */
static bool fdt_redistributor_regions(const struct fdt_node *node,
				      uint32_t *count)
{
	int c = fdt_redistributor_regions_cells(fdt_base(&node->fdt),
						node->offset);
	if (c < 0) {
		return false;
	}
	*count = (uint64_t)c;
	return true;
}

static bool fdt_find_gics(const struct fdt *fdt,
			  struct mem_range *gic_mem_ranges, uint32_t *gic_count)
{
	struct fdt_node n;
	struct memiter data;
	size_t addr_size;
	size_t size_size;
	uint8_t rdist_reg_idx = 0;

	if (!fdt_find_node(fdt, "/interrupt-controller", &n) ||
	    !fdt_address_size(&n, &addr_size) ||
	    !fdt_size_size(&n, &size_size) ||
	    !fdt_redistributor_regions(&n, gic_count)) {
		dlog_info(
			"Unable to find '/interrupt-controller. Using default "
			"configuration.'\n");
		/*
		 * Initialise the default GICD, GICR memory ranges and GIC count
		 */
		gic_mem_ranges[0].begin = pa_init(GICD_BASE);
		gic_mem_ranges[0].end = pa_init(GICD_BASE + GICD_SIZE);
		gic_mem_ranges[1].begin = pa_init(GICR_BASE);
		gic_mem_ranges[1].end = pa_init(
			GICR_BASE + GICR_FRAMES * GIC_REDIST_SIZE_PER_PE);
		*gic_count = 1;
		return true;
	}
	if (!fdt_read_property(&n, "reg", &data)) {
		dlog_error("Unable to read property 'reg'\n");
		return false;
	}
	/* Traverse all memory ranges within this node. */
	while (memiter_size(&data)) {
		uintpaddr_t addr;
		size_t len;

		CHECK(fdt_parse_number(&data, addr_size, &addr));
		CHECK(fdt_parse_number(&data, size_size, &len));
		gic_mem_ranges[rdist_reg_idx].begin = pa_init(addr);
		gic_mem_ranges[rdist_reg_idx].end = pa_init(addr + len);
		rdist_reg_idx++;
	}
	return true;
}

uint64_t read_gicr_typer_reg(uintptr_t gicr_frame_addr)
{
	return io_read64(IO64_C(gicr_frame_addr + GICR_TYPER));
}

uint64_t read_gicd_typer_reg(uintptr_t base)
{
	return io_read32(IO32_C(base + GICD_TYPER));
}

/*
 * This function calculates the core position from the affinity values
 * provided by the GICR_TYPER register. This function may return MAX_CORES
 * if typer_reg doesn't match a known core.
 */
static inline uint32_t gicr_affinity_to_core_pos(uint64_t typer_reg)
{
	uint64_t aff3;
	uint64_t aff2;
	uint64_t aff1;
	uint64_t aff0;
	uint64_t reg;

	aff3 = (typer_reg >> RDIST_AFF3_SHIFT) & (0xff);
	aff2 = (typer_reg >> RDIST_AFF2_SHIFT) & (0xff);
	aff1 = (typer_reg >> RDIST_AFF1_SHIFT) & (0xff);
	aff0 = (typer_reg >> RDIST_AFF0_SHIFT) & (0xff);

	/* Construct mpidr based on above affinities. */
	reg = (aff3 << MPIDR_AFF3_SHIFT) | (aff2 << MPIDR_AFF2_SHIFT) |
	      (aff1 << MPIDR_AFF1_SHIFT) | (aff0 << MPIDR_AFF0_SHIFT);

	return arch_affinity_to_core_pos(reg);
}

static inline void populate_redist_base_addrs(struct mem_range *gic_mem_ranges,
					      uint32_t num_gic_rdist)
{
	uintptr_t current_rdist_frame;
	uint64_t typer_reg;
	uint32_t core_idx;
	uint32_t gicr_idx = 0;

	/*
	 * GICR mem range starts from index 1. GICD mem range is index 0.
	 */
	current_rdist_frame = gic_mem_ranges[gicr_idx + 1].begin.pa;

	while (gicr_idx < num_gic_rdist) {
		typer_reg = read_gicr_typer_reg(current_rdist_frame);
		core_idx = gicr_affinity_to_core_pos(typer_reg);

		/*
		 * If the PE in redistributor does not exist, core_idx
		 * will be MAX_CPUS, then do not fill up frame entry
		 * and just move to next frame.
		 */
		if (core_idx < MAX_CPUS) {
			plat_gicv3_driver.all_redist_frames[core_idx] =
				current_rdist_frame;
		}

		/* Check if this is the last GICR frame for the specific chip */
		if (typer_reg & REDIST_LAST_FRAME_MASK) {
			gicr_idx++;
			current_rdist_frame =
				gic_mem_ranges[gicr_idx + 1].begin.pa;
			continue;
		}

		current_rdist_frame += GIC_REDIST_FRAMES_OFFSET;
	}
}

/**
 * Currently, TF-A has complete access to GIC driver and configures
 * GIC Distributor, GIC Re-distributor and CPU interfaces as needed.
 */
void gicv3_distif_init(void)
{
	/* TODO: Currently, we skip this. */
	return;

	/* Enable G1S and G1NS interrupts. */
	gicd_set_ctlr(
		plat_gicv3_driver.dist_base,
		CTLR_ENABLE_G1NS_BIT | CTLR_ENABLE_G1S_BIT | CTLR_ARE_S_BIT,
		RWP_TRUE);
}

void gicv3_rdistif_init(uint32_t core_pos)
{
	/* TODO: Currently, we skip this. */
	(void)core_pos;
}

void gicv3_cpuif_enable(uint32_t core_pos)
{
	/* TODO: Currently, we skip this. */
	(void)core_pos;
}

void gicv3_send_sgi(uint32_t sgi_id, bool send_to_all, uint64_t mpidr_target,
		    bool to_this_security_state)
{
	uint64_t sgir;
	uint64_t irm;

	CHECK(is_sgi_ppi(sgi_id));

	sgir = (sgi_id & SGIR_INTID_MASK) << SGIR_INTID_SHIFT;

	/* Check the interrupt routing mode. */
	if (send_to_all) {
		irm = 1;
	} else {
		irm = 0;

		/*
		 * Find the affinity path of the PE for which SGI will be
		 * generated.
		 */

		uint64_t aff0;
		uint64_t aff1;
		uint64_t aff2;
		uint64_t aff3;

		/*
		 * Target List is a one hot encoding representing which cores
		 * will be delivered the interrupt. At least one has to be
		 * enabled.
		 */
		aff3 = (mpidr_target >> MPIDR_AFF3_SHIFT) & (0xff);
		aff2 = (mpidr_target >> MPIDR_AFF2_SHIFT) & (0xff);
		aff1 = (mpidr_target >> MPIDR_AFF1_SHIFT) & (0xff);
		aff0 = (mpidr_target >> MPIDR_AFF0_SHIFT) & (0xff);

		/* Populate the various affinity fields. */
		sgir |= ((aff3 & SGIR_AFF_MASK) << SGIR_AFF3_SHIFT) |
			((aff2 & SGIR_AFF_MASK) << SGIR_AFF2_SHIFT) |
			((aff1 & SGIR_AFF_MASK) << SGIR_AFF1_SHIFT);

		/* Construct the SGI target affinity. */
		sgir |= ((1U << aff0) & SGIR_TGT_MASK) << SGIR_TGT_SHIFT;
	}

	/* Populate the Interrupt Routing Mode field. */
	sgir |= (irm & SGIR_IRM_MASK) << SGIR_IRM_SHIFT;

	if (to_this_security_state) {
		write_msr(ICC_SGI1R_EL1, sgir);
	} else {
		write_msr(ICC_ASGI1R_EL1, sgir);
	}

	isb();
}

#if GIC_EXT_INTID
/*******************************************************************************
 * Helper function to get the maximum ESPI INTID + 1.
 ******************************************************************************/
unsigned int gicv3_get_espi_limit(uintptr_t gicd_base)
{
	unsigned int typer_reg = read_gicd_typer_reg(gicd_base);

	/* Check if extended SPI range is implemented */
	if ((typer_reg & TYPER_ESPI) != 0U) {
		/*
		 * (maximum ESPI INTID + 1) is equal to
		 * 32 * (GICD_TYPER.ESPI_range + 1) + 4096
		 */
		return ((((typer_reg >> TYPER_ESPI_RANGE_SHIFT) &
			  TYPER_ESPI_RANGE_MASK) +
			 1U)
			<< 5) +
		       MIN_ESPI_ID;
	}

	return 0U;
}
#endif /* GIC_EXT_INTID */

bool gicv3_driver_init(struct mm_stage1_locked stage1_locked,
		       struct mpool *ppool, struct mem_range *gic_mem_ranges,
		       uint32_t num_gic_rdist)
{
	void *base_addr;
	uint32_t gic_version;
	uint32_t reg_pidr;
	uint32_t typer_reg;
	uint32_t gicr_idx;

	base_addr = mm_identity_map(stage1_locked, pa_init(GICD_BASE),
				    pa_init(GICD_BASE + GICD_SIZE),
				    MM_MODE_R | MM_MODE_W | MM_MODE_D, ppool);
	if (base_addr == NULL) {
		dlog_error("Could not map GICv3 into Hafnium memory map\n");
		return false;
	}

	plat_gicv3_driver.dist_base = (uintptr_t)base_addr;
	typer_reg = read_gicd_typer_reg(plat_gicv3_driver.dist_base);

	/* Ensure GIC implementation supports two security states. */
	CHECK((typer_reg & TYPER_SEC_EXTN) == TYPER_SEC_EXTN);

	for (gicr_idx = 0; gicr_idx < num_gic_rdist; gicr_idx++) {
		/*
		 * GICR mem range starts from index 1. GICD mem range is index 0
		 */
		base_addr = mm_identity_map(
			stage1_locked, gic_mem_ranges[gicr_idx + 1].begin,
			gic_mem_ranges[gicr_idx + 1].end,
			MM_MODE_R | MM_MODE_W | MM_MODE_D, ppool);

		if (base_addr == NULL) {
			dlog_error(
				"Could not map GICv3 into Hafnium memory "
				"map\n");
			return false;
		}
	}

	/* Check GIC version reported by the Peripheral register. */
	reg_pidr = gicd_read_pidr2(plat_gicv3_driver.dist_base);
	gic_version = (reg_pidr >> PIDR2_ARCH_REV_SHIFT) & PIDR2_ARCH_REV_MASK;

#if GIC_VERSION == 3
	CHECK(gic_version == ARCH_REV_GICV3);
#elif GIC_VERSION == 4
	CHECK(gic_version == ARCH_REV_GICV4);
#endif
	populate_redist_base_addrs(gic_mem_ranges, num_gic_rdist);

#if GIC_EXT_INTID
	CHECK((typer_reg & TYPER_ESPI) == TYPER_ESPI);
	CHECK(gicv3_get_espi_limit(plat_gicv3_driver.dist_base) != 0);
#endif
	return true;
}

bool plat_interrupts_controller_driver_init(
	const struct fdt *fdt, struct mm_stage1_locked stage1_locked,
	struct mpool *ppool)
{
	struct mem_range gic_mem_ranges[MAX_CHIPS];
	uint32_t num_gic_rdist;
	uint32_t chip_idx = 0;

	while (chip_idx < MAX_CHIPS) {
		gic_mem_ranges[chip_idx].begin = pa_init(0);
		gic_mem_ranges[chip_idx].end = pa_init(0);
		chip_idx++;
	}

	fdt_find_gics(fdt, gic_mem_ranges, &num_gic_rdist);

	if (!gicv3_driver_init(stage1_locked, ppool, gic_mem_ranges,
			       num_gic_rdist)) {
		dlog_error("Failed to initialize GICv3 driver\n");
		return false;
	}

	gicv3_distif_init();
	gicv3_rdistif_init(arch_find_core_pos());

	return true;
}

void plat_interrupts_controller_hw_init(struct cpu *c)
{
	(void)c;
	gicv3_cpuif_enable(arch_find_core_pos());
}

void plat_interrupts_set_priority_mask(uint8_t min_priority)
{
	write_msr(ICC_PMR_EL1, min_priority);
}

uint8_t plat_interrupts_get_priority_mask(void)
{
	return read_msr(ICC_PMR_EL1);
}

void plat_interrupts_set_priority(uint32_t id, uint32_t core_pos,
				  uint32_t priority)
{
	gicv3_set_interrupt_priority(id, core_pos, priority);
}

void plat_interrupts_enable(uint32_t id, uint32_t core_pos)
{
	gicv3_enable_interrupt(id, core_pos);
}

void plat_interrupts_disable(uint32_t id, uint32_t core_pos)
{
	gicv3_disable_interrupt(id, core_pos);
}

void plat_interrupts_set_type(uint32_t id, uint32_t type)
{
	gicv3_set_interrupt_type(id, arch_find_core_pos(), type);
}

uint32_t plat_interrupts_get_type(uint32_t id)
{
	return gicv3_get_interrupt_type(id, arch_find_core_pos());
}

uint32_t plat_interrupts_get_pending_interrupt_id(void)
{
	return gicv3_get_pending_interrupt_id();
}

void plat_interrupts_end_of_interrupt(uint32_t id)
{
	gicv3_end_of_interrupt(id);
}

/**
 * Configure Group, priority, edge/level of the interrupt and enable it.
 */
void plat_interrupts_configure_interrupt(struct interrupt_descriptor int_desc)
{
	uint32_t core_idx = arch_find_core_pos();
	uint32_t config = GIC_INTR_CFG_LEVEL;
	uint32_t intr_num = int_desc.interrupt_id;

	CHECK(core_idx < MAX_CPUS);
	CHECK(IS_SGI_PPI(intr_num) || IS_SPI(intr_num));

	/* Configure the interrupt as either G1S or G1NS. */
	if (int_desc.sec_state != 0) {
		gicv3_set_interrupt_type(intr_num, core_idx, INTR_GROUP1S);
	} else {
		gicv3_set_interrupt_type(intr_num, core_idx, INTR_GROUP1NS);
	}

	/* Program the interrupt priority. */
	gicv3_set_interrupt_priority(intr_num, core_idx, int_desc.priority);

	if (int_desc.config == 0) {
		/* Interrupt is edge-triggered. */
		config = GIC_INTR_CFG_EDGE;
	}

	/* Set interrupt configuration. */
	if (is_sgi_ppi(intr_num)) {
		/* GICR interface. */
		gicr_set_icfgr(plat_gicv3_driver.all_redist_frames[core_idx],
			       intr_num, config);
	} else {
		/* GICD interface. */
		gicd_set_icfgr(plat_gicv3_driver.dist_base, intr_num, config);
	}

	/*
	 * Target SPI to primary PE using affinity routing if no PE was
	 * specified in the manifest. If one was specified, target the interrupt
	 * to the corresponding PE.
	 */
	if (IS_SPI(intr_num)) {
		uint64_t gic_affinity_val;

		if (int_desc.mpidr_valid) {
			gic_affinity_val = gicd_irouter_val_from_mpidr(
				int_desc.mpidr, GICV3_IRM_PE);
		} else {
			gic_affinity_val = gicd_irouter_val_from_mpidr(
				read_msr(MPIDR_EL1), 0U);
		}
		gicd_write_irouter(plat_gicv3_driver.dist_base, intr_num,
				   gic_affinity_val);
	}

	if (int_desc.enabled) {
		/* Enable the interrupt now. */
		gicv3_enable_interrupt(intr_num, core_idx);
	}
}

void plat_interrupts_send_sgi(uint32_t id, struct cpu *cpu,
			      bool to_this_security_state)
{
	gicv3_send_sgi(id, false, cpu->id, to_this_security_state);
}

/**
 * Reconfigure the interrupt based on the interrupt descriptor.
 */
void plat_interrupts_reconfigure_interrupt(struct interrupt_descriptor int_desc)
{
	assert(int_desc.valid);

	gicv3_disable_interrupt(int_desc.interrupt_id, arch_find_core_pos());

	/*
	 * Interrupt already disabled above. Proceed to (re)configure the
	 * interrupt and enable it, if permitted.
	 */
	plat_interrupts_configure_interrupt(int_desc);
}
