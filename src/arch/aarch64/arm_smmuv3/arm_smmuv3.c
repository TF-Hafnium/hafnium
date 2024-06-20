/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "arm_smmuv3.h"

#include "hf/dlog.h"
#include "hf/io.h"
#include "hf/panic.h"
#include "hf/static_assert.h"

#define MAX_ATTEMPTS 50000

static struct smmuv3_driver arm_smmuv3;
static unsigned int smmu_instance = 0;

static uint32_t find_offset(uint32_t secure, uint32_t non_secure)
{
#if SECURE_WORLD == 1
	/*
	 * Workaround necessary to deal with the following compilation error:
	 * error: parameter 'non_secure' is unused
	 * [misc-unused-parameters,-warnings-as-errors]
	 */
	(void)non_secure;

	return secure;
#else
	(void)secure;
	return non_secure;
#endif
}

static bool smmuv3_poll(void *addr, uint32_t offset, uint32_t exp,
			uint32_t mask)
{
	uint32_t observed;
	uint32_t attempts;
	void *mem_addr = (uint8_t *)addr + offset;

	attempts = 0;
	while (attempts++ < MAX_ATTEMPTS) {
		observed = mmio_read32(mem_addr);
		if ((observed & mask) == (exp & mask)) {
			return true;
		}
	}

	dlog_verbose("SMMUv3: timeout polling register at %p\n", mem_addr);

	return false;
}

/*
 * Control the default translation behaviour of SMMU for incoming streams when
 * it is disabled. The behaviour is controlled by SMMU_(S)_GBPA register.
 * Program the register to bypass the incoming transactions and use incoming
 * attributes.
 */
static void smmuv3_disabled_translation(struct smmuv3_driver *smmuv3)
{
	uint32_t gbpa_reg;
	uint32_t gbpa_update_set;
	uint32_t offset;

	gbpa_reg = COMPOSE(BYPASS_GBPA, ABORT_SHIFT, ABORT_MASK);
	gbpa_reg =
		gbpa_reg | COMPOSE(INCOMING_CFG, INSTCFG_SHIFT, INSTCFG_MASK);
	gbpa_reg =
		gbpa_reg | COMPOSE(INCOMING_CFG, PRIVCFG_SHIFT, PRIVCFG_MASK);
	gbpa_reg = gbpa_reg | COMPOSE(INCOMING_CFG, SHCFG_SHIFT, SHCFG_MASK);
	gbpa_reg =
		gbpa_reg | COMPOSE(INCOMING_CFG, ALLOCFG_SHIFT, ALLOCFG_MASK);
	gbpa_reg = gbpa_reg | COMPOSE(INCOMING_CFG, MTCFG_SHIFT, MTCFG_MASK);
	gbpa_update_set = (1 << UPDATE_SHIFT);

	offset = find_offset(S_GBPA, GBPA);

	dlog_verbose("SMMUv3: write to (S_)GBPA\n");
	mmio_write32_offset(smmuv3->base_addr, offset,
			    gbpa_reg | gbpa_update_set);

	if (!smmuv3_poll(smmuv3->base_addr, offset, gbpa_reg,
			 (1 << UPDATE_SHIFT))) {
		panic("SMMUv3: Failed to update Gloal Bypass Attribute\n");
	}
}

static bool smmuv3_reset(struct smmuv3_driver *smmuv3)
{
	/* Configure the behaviour of SMMU when disabled */
	smmuv3_disabled_translation(smmuv3);

	/*
	 * Disable SMMU using SMMU_(S)_CR0.SMMUEN bit. This is necessary
	 * for driver to configure SMMU.
	 */
	uint32_t data_cr0;
	uint32_t offset_cr0 = find_offset(S_CR0, CR0);
	uint32_t offset_cr0_ack = find_offset(S_CR0_ACK, CR0_ACK);

	dlog_verbose("SMMUv3: write to (S_)CR0\n");

	data_cr0 = mmio_read32_offset(smmuv3->base_addr, offset_cr0);
	data_cr0 = data_cr0 & SMMUEN_CLR_MASK;
	mmio_write32_offset(smmuv3->base_addr, offset_cr0, data_cr0);

	if (!smmuv3_poll(smmuv3->base_addr, offset_cr0_ack, data_cr0,
			 SMMUEN_MASK)) {
		dlog_error("SMMUv3: Failed to disable SMMU\n");
		return false;
	}

	return true;
}

static bool smmuv3_identify_features(struct smmuv3_driver *smmuv3)
{
	uint32_t idr0;
	uint32_t arch_version;
	uint32_t xlat_format;

	arch_version = mmio_read32_offset(smmuv3->base_addr, AIDR);
	arch_version = EXTRACT(arch_version, ARCH_REV_SHIFT, ARCH_REV_MASK);

	if (arch_version > 2) {
		dlog_error("SMMUv3: Unknown architecture version\n");
		return false;
	}

	smmuv3->prop.minor_version = arch_version;
	idr0 = mmio_read32_offset(smmuv3->base_addr, IDR0);

	switch (EXTRACT(idr0, ST_LEVEL_SHIFT, ST_LEVEL_MASK)) {
	case (TWO_LVL_STR_TABLE):
		smmuv3->prop.lvl2_str_table = true;
		/* Fall through */
	case (LINEAR_STR_TABLE):
		smmuv3->prop.linear_str_table = true;
		break;
	default:
		dlog_error(
			"SMMUv3: Illegal value for Multi-level Stream table "
			"support\n");
		return false;
	}

	smmuv3->prop.endian = EXTRACT(idr0, TTENDIAN_SHIFT, TTENDIAN_MASK);
	if (smmuv3->prop.endian == RES_ENDIAN) {
		dlog_error(
			"SMMUv3: Unsupported endianness for translation table "
			"walks\n");
		return false;
	}

	if (EXTRACT(idr0, BTM_SHIFT, BTM_MASK)) {
		smmuv3->prop.broadcast_TLB = true;
	} else {
		smmuv3->prop.broadcast_TLB = false;
		dlog_error(
			"SMMUv3: Broadcast TLB maintenance not supported "
			"in hardware\n");
	}

	xlat_format = EXTRACT(idr0, TTF_SHIFT, TTF_MASK);

	switch (xlat_format) {
	case AARCH32_TTF:
		dlog_error(
			"SMMUv3: Driver currently supports only AArch64 "
			"translation "
			"table format\n");
		return false;
	case AARCH64_TTF:
	case AARCH32_64_TTF:
		break;
	case RES_TTF:
	default:
		dlog_error("SMMUv3: Unsupported translation table format\n");
		return false;
	}

	smmuv3->prop.xlat_format = xlat_format;
	smmuv3->prop.xlat_stages = EXTRACT(idr0, XLAT_STG_SHIFT, XLAT_STG_MASK);

	return true;
}

static bool smmuv3_queue_sizes(struct smmuv3_driver *smmuv3)
{
	uint32_t idr1;
	uint32_t size;
	uint32_t preset;

	idr1 = mmio_read32_offset(smmuv3->base_addr, IDR1);
	preset = EXTRACT(idr1, PRESET_SHIFT, PRESET_MASK);

	/*
	 * At the momemt, we do not support SMMU implementations which have
	 * either Table or Queue base addresses fixed
	 */
	if (preset != 0) {
		dlog_error(
			"SMMUv3: Driver does not support TABLES_PRESET, "
			"QUEUES_PRESET\n");
		return false;
	}

	size = EXTRACT(idr1, CMDQS_SHIFT, CMDQS_MASK);

	if (size > CMDQS_MAX) {
		dlog_error(
			"SMMUv3: Command queue entries(log2) cannot exceed "
			"%d\n",
			CMDQS_MAX);
		return false;
	}

	smmuv3->prop.cmdq_entries_log2 = size;
	size = EXTRACT(idr1, EVTQS_SHIFT, EVTQS_MASK);

	if (size > EVTQS_MAX) {
		dlog_error(
			"SMMUv3: Event queue entries(log2) cannot exceed %d\n",
			EVTQS_MAX);
		return false;
	}

	smmuv3->prop.evtq_entries_log2 = size;

	/*
	 * SubStreamID Size for both Secure and Non-secure states is determined
	 * by SMMU_IDR1 register.
	 */
	size = EXTRACT(idr1, SUB_SID_SHIFT, SUB_SID_SIZE_MASK);

	if (size > SUB_SID_SIZE_MAX) {
		dlog_error("SMMuv3: Max bits of SubStreamID cannot exceed %d\n",
			   SUB_SID_SIZE_MAX);
		return false;
	}

	smmuv3->prop.sub_stream_n_bits = size;

#if SECURE_WORLD == 1
	uint32_t s_idr1;

	s_idr1 = mmio_read32_offset(smmuv3->base_addr, S_IDR1);
	size = EXTRACT(s_idr1, SID_SHIFT, SID_SIZE_MASK);
#else
	size = EXTRACT(idr1, SID_SHIFT, SID_SIZE_MASK);
#endif

	if (size > SID_SIZE_MAX) {
		dlog_error("SMMUv3: Max bits of StreamID cannot exceed %d\n",
			   SID_SIZE_MAX);
		return false;
	}

	if (size >= 7 && smmuv3->prop.linear_str_table) {
		dlog_error(
			"SMMUv3: Linear Stream Table cannot be supported when "
			"StreamID bits > 7\n");
		return false;
	}

	smmuv3->prop.stream_n_bits = size;
	return true;
}

static bool smmuv3_xlat_support(struct smmuv3_driver *smmuv3)
{
	uint32_t idr5;
	uint32_t data_cr1;
	uint32_t data_cr2;
	uint32_t offset;
	uint64_t oas;
	uint64_t oas_bits;

#if SECURE_WORLD == 1
	uint32_t s_idr1;

	s_idr1 = mmio_read32_offset(smmuv3->base_addr, S_IDR1);

	if (!(s_idr1 & SECURE_IMPL_MASK)) {
		dlog_error("SMMUv3 does not implement secure state\n");
		return false;
	}
	/*
	 * If Secure state is implemented, Stage 1 must be supported
	 * i.e., SMMU_IDR0.S1P=1
	 */
	if ((smmuv3->prop.xlat_stages == NO_STG1_STG2) ||
	    (smmuv3->prop.xlat_stages == STG2_ONLY)) {
		dlog_error(
			"SMMUv3: Stage 1 translation needs to be supported\n");
		return false;
	}

	/*
	 * SMMU_S_IDR1.SEL2 indicates support for both S-EL2 and Secure stage 2
	 */
	if (!(s_idr1 & SEL2_STG2_SUPPORT)) {
		dlog_error(
			"SMMUv3: Secure stage 2 translation not supported!\n");
		return false;
	}
#endif
	idr5 = mmio_read32_offset(smmuv3->base_addr, IDR5);
	oas_bits = EXTRACT(idr5, OAS_SHIFT, OAS_MASK);

	uint64_t ias_aarch32 = 0;
	uint64_t ias_aarch64 = 0;

	/* Translation Table format support for AArch32 and AArch64 */
	bool ttf_aarch32 = false;
	bool ttf_aarch64 = true;

	/* We assume AArch64 translation table format is supported */
	if (smmuv3->prop.xlat_format == AARCH32_64_TTF) {
		ttf_aarch32 = true;
	}

	/* Output address size */
	switch (oas_bits) {
	case OAS_32BITS:
		oas = 32;
		break;
	case OAS_36BITS:
		oas = 36;
		break;
	case OAS_40BITS:
		oas = 40;
		break;
	case OAS_42BITS:
		oas = 42;
		break;
	case OAS_44BITS:
		oas = 44;
		break;
	case OAS_48BITS:
		oas = 48;
		break;
	case OAS_52BITS:
		if (smmuv3->prop.minor_version == 0) {
			dlog_error(
				"SMMUv3: 52 bit Output address size not "
				"supported for SMMUv3.0\n");
			return false;
		}
		oas = 52;
		break;
	case OAS_RES:
	default:
		dlog_error("SMMUv3: Output address size unknown\n");
		return false;
	}

	/*
	 * T1 = (SMMU_IDR0.TTF[0] == 1 ? 40 : 0);
	 * T2 = (SMMU_IDR0.TTF[1] == 1 ? OAS : 0);
	 * IAS = MAX(T1, T2);
	 */
	smmuv3->prop.oas = oas;
	smmuv3->prop.oas_encoding = oas_bits;
	ias_aarch32 = ttf_aarch32 ? 40 : 0;
	ias_aarch64 = ttf_aarch64 ? smmuv3->prop.oas : 0;
	smmuv3->prop.ias = ias_aarch64;

	if (ias_aarch32 > ias_aarch64) {
		smmuv3->prop.ias = ias_aarch32;
	}

	dlog_verbose("SMMUv3: Input Addr: %lu-bits, Output Addr: %lu-bits\n",
		     smmuv3->prop.ias, smmuv3->prop.oas);

	/*
	 * Set cacheability and shareablity attributes for Table and Queue
	 * access through SMMU_(S)_CR1 register
	 */
	data_cr1 = COMPOSE(CR1_INSH, TAB_SH_SHIFT, SH_MASK);
	data_cr1 |= COMPOSE(CR1_WBCACHE, TAB_OC_SHIFT, OC_MASK);
	data_cr1 |= COMPOSE(CR1_WBCACHE, TAB_IC_SHIFT, IC_MASK);
	data_cr1 |= COMPOSE(CR1_INSH, QUE_SH_SHIFT, SH_MASK);
	data_cr1 |= COMPOSE(CR1_WBCACHE, QUE_OC_SHIFT, OC_MASK);
	data_cr1 |= COMPOSE(CR1_WBCACHE, QUE_IC_SHIFT, IC_MASK);

	offset = find_offset(S_CR1, CR1);
	mmio_write32_offset(smmuv3->base_addr, offset, data_cr1);

	/* Program SMMU_(S)_CR2 register */
	offset = find_offset(S_CR2, CR2);
	data_cr2 = mmio_read32_offset(smmuv3->base_addr, offset);

	/*
	 * Configure SMMU to participate in broadcast TLB maintenance if the
	 * SMMU implementation supports it.
	 */
	if (smmuv3->prop.broadcast_TLB) {
		/* Clear and program PTM bit*/
		data_cr2 &= ~(COMPOSE(1, PTM_SHIFT, PTM_MASK));
		data_cr2 |= COMPOSE(PTM_ENABLE, PTM_SHIFT, PTM_MASK);
		mmio_write32_offset(smmuv3->base_addr, offset, data_cr2);
	}

	return true;
}

static bool smmuv3_configure_cmdq(struct smmuv3_driver *smmuv3,
				  struct mpool *pool)
{
	uint32_t cmdq_size;
	uint64_t cmdq_base_reg;
	void *q_base;

	cmdq_size = (1 << smmuv3->prop.cmdq_entries_log2) * CMD_SIZE;
	dlog_verbose("SMMUv3: Total CMDQ entries: %d\n",
		     (1 << smmuv3->prop.cmdq_entries_log2));

	q_base = mpool_alloc_contiguous(pool, (cmdq_size / FFA_PAGE_SIZE) + 1,
					1);

	if (q_base == NULL) {
		dlog_error(
			"SMMUv3: Could not allocate memory for command "
			"queue\n");
		return false;
	}

	dlog_verbose("SMMUv3: Memory allocated at %p for CMDQ\n", q_base);
	smmuv3->cmd_queue.q_base = q_base;

	cmdq_base_reg = (uint64_t)q_base & GEN_MASK(51, 5);
	cmdq_base_reg = cmdq_base_reg | (1ULL << RA_HINT_SHIFT);
	cmdq_base_reg = cmdq_base_reg | smmuv3->prop.cmdq_entries_log2;

	uint32_t offset_cmdq_cons;
	uint32_t offset_cmdq_prod;
	uint32_t offset_cmdq_base;

	offset_cmdq_cons = find_offset(S_CMDQ_CONS, CMDQ_CONS);
	offset_cmdq_prod = find_offset(S_CMDQ_PROD, CMDQ_PROD);
	offset_cmdq_base = find_offset(S_CMDQ_BASE, CMDQ_BASE);

	smmuv3->cmd_queue.cons_reg_base =
		(void *)((uint8_t *)smmuv3->base_addr + offset_cmdq_cons);
	smmuv3->cmd_queue.prod_reg_base =
		(void *)((uint8_t *)smmuv3->base_addr + offset_cmdq_prod);

	/* Initialize SMMU_CMDQ_BASE register */
	dlog_verbose("SMMUv3: write to (S_)CMDQ_BASE\n");
	mmio_write64_offset(smmuv3->base_addr, offset_cmdq_base, cmdq_base_reg);

	/* Initialize SMMU_CMDQ_CONS and SMMU_CMDQ_PROD registers */
	dlog_verbose("SMMUv3: write to (S_)CMDQ_CONS, (S_)CMDQ_PROD\n");
	mmio_write32(smmuv3->cmd_queue.cons_reg_base, 0);
	mmio_write32(smmuv3->cmd_queue.prod_reg_base, 0);

	return true;
}

static bool smmuv3_configure_evtq(struct smmuv3_driver *smmuv3,
				  struct mpool *pool)
{
	uint32_t evtq_size;
	uint32_t offset_evtq_base;
	uint32_t offset_evtq_prod;
	uint32_t offset_evtq_cons;
	uint64_t evtq_base_reg;
	void *q_base;

	evtq_size = (1 << smmuv3->prop.evtq_entries_log2) * EVT_RECORD_SIZE;
	dlog_verbose("SMMUv3: Total EVTQ entries: %d\n",
		     (1 << smmuv3->prop.evtq_entries_log2));

	q_base = mpool_alloc_contiguous(pool, (evtq_size / FFA_PAGE_SIZE) + 1,
					1);

	if (q_base == NULL) {
		dlog_error(
			"SMMUv3: Could not allocate memory for event queue\n");
		return false;
	}

	dlog_verbose("SMMUv3: Memory allocated at %p for EVTQ\n", q_base);
	smmuv3->evt_queue.q_base = q_base;
	evtq_base_reg = (uint64_t)q_base & GEN_MASK(51, 5);
	evtq_base_reg = evtq_base_reg | (1ULL << WA_HINT_SHIFT);
	evtq_base_reg = evtq_base_reg | smmuv3->prop.evtq_entries_log2;

	dlog_verbose("SMMUv3: write to (S_)EVTQ_BASE\n");
	offset_evtq_base = find_offset(S_EVTQ_BASE, EVTQ_BASE);
	mmio_write64_offset(smmuv3->base_addr, offset_evtq_base, evtq_base_reg);

	dlog_verbose("SMMUv3: write to (S_)EVTQ_PROD,(S_)EVTQ_CONS\n");
	offset_evtq_prod = find_offset(S_EVTQ_PROD, EVTQ_PROD);
	offset_evtq_cons = find_offset(S_EVTQ_CONS, EVTQ_CONS);

	mmio_write32_offset(smmuv3->base_addr, offset_evtq_prod, 0);
	mmio_write32_offset(smmuv3->base_addr, offset_evtq_cons, 0);

	return true;
}

static inline void clear_ste(uint64_t *data)
{
	unsigned int i;

	for (i = 0; i < STE_SIZE_DW; i++) {
		data[i] = 0;
	}
}

static inline void write_ste(uint64_t *st_entry, const uint64_t *data)
{
	int i;

	/*
	 * Mark the stream table entry as invalid to avoid race condition
	 * STE.V = 0 (bit 0) of first double word
	 */
	st_entry[0] = 0;

	/*
	 * Write to memory from upper double word of Stream Table entry such
	 * that the bottom double word which has the STE.Valid bit is written
	 * last.
	 */
	for (i = STE_SIZE_DW - 1U; i >= 0; i--) {
		st_entry[i] = data[i];
	}

	/* Ensure written data(STE) is observable to SMMU by performing DSB */
	dsb(sy);
}

static void smmuv3_invalidate_stes(struct smmuv3_driver *smmuv3)
{
	unsigned int i;
	unsigned int ste_count;

	/* Each stream table entry is 64 bytes wide i.e., 8 Double Words*/
	uint64_t ste_data[STE_SIZE_DW];
	uint64_t *ste_addr;

	clear_ste(ste_data);
	ste_addr = (uint64_t *)smmuv3->strtab_cfg.base;
	ste_count = (1 << smmuv3->prop.stream_n_bits);

	for (i = 0; i < ste_count; i++) {
		write_ste(ste_addr, ste_data);
		ste_addr += STE_SIZE_DW;
	}
}

static bool smmuv3_configure_str_table(struct smmuv3_driver *smmuv3,
				       struct mpool *pool)
{
	uint32_t strtab_size;
	uint32_t strtab_cfg_reg;
	uint64_t strtab_base_reg;
	uint32_t offset_strtab_base_cfg;
	uint32_t offset_strtab_base;
	void *tbl_base;

	strtab_size = (1 << smmuv3->prop.stream_n_bits) * STE_SIZE;
	dlog_verbose("SMMUv3 Total StreamTable entries: %d\n",
		     (1 << smmuv3->prop.stream_n_bits));

	tbl_base = mpool_alloc_contiguous(pool,
					  (strtab_size / FFA_PAGE_SIZE) + 1, 1);

	if (tbl_base == NULL) {
		dlog_error(
			"SMMUv3: Could not allocate memory for stream table "
			"entries\n");
		return false;
	}

	dlog_verbose("SMMUv3: Memory allocated at %p for Stream Table\n",
		     tbl_base);
	smmuv3->strtab_cfg.base = tbl_base;
	strtab_base_reg = (uint64_t)tbl_base & GEN_MASK(51, 6);
	strtab_base_reg = strtab_base_reg | (1ULL << RA_HINT_SHIFT);

	/* We assume Linear format for stream table */
	strtab_cfg_reg = LINEAR_STR_TABLE << STR_FMT_SHIFT;
	strtab_cfg_reg = strtab_cfg_reg | smmuv3->prop.stream_n_bits;

	dlog_verbose("SMMUv3: write to (S_)STRTAB_BASE_CFG\n");
	offset_strtab_base_cfg =
		find_offset(S_STRTAB_BASE_CFG, STRTAB_BASE_CFG);
	mmio_write32_offset(smmuv3->base_addr, offset_strtab_base_cfg,
			    strtab_cfg_reg);

	dlog_verbose("SMMUv3: write to (S_)STRTAB_BASE\n");
	offset_strtab_base = find_offset(S_STRTAB_BASE, STRTAB_BASE);
	mmio_write64_offset(smmuv3->base_addr, offset_strtab_base,
			    strtab_base_reg);

	/* Mark STE as invalid */
	smmuv3_invalidate_stes(smmuv3);

	return true;
}

static bool smmuv3_configure_queues(struct smmuv3_driver *smmuv3,
				    struct mpool *pool)
{
	if (!smmuv3_queue_sizes(smmuv3)) {
		return false;
	}

	if (!smmuv3_configure_cmdq(smmuv3, pool)) {
		return false;
	}

	if (!smmuv3_configure_evtq(smmuv3, pool)) {
		return false;
	}

	return true;
}

static void construct_inv_all_cfg(uint64_t *cmd)
{
	uint32_t stream = find_offset(S_STREAM, NS_STREAM);

	cmd[0] = COMPOSE(OP_CFGI_ALL, OP_SHIFT, OP_MASK);
	cmd[0] |= COMPOSE(stream, SSEC_SHIFT, SSEC_MASK);
	cmd[1] = COMPOSE(SID_ALL, SID_RANGE_SHIFT, SID_RANGE_MASK);
}

static void construct_inv_ste_cfg(uint64_t *cmd, uint32_t sid)
{
	uint32_t stream = find_offset(S_STREAM, NS_STREAM);

	cmd[0] = COMPOSE(OP_CFGI_STE, OP_SHIFT, OP_MASK);
	cmd[0] |= COMPOSE(stream, SSEC_SHIFT, SSEC_MASK);
	cmd[0] |= COMPOSE((unsigned long)sid, CMD_SID_SHIFT, CMD_SID_MASK);
	cmd[1] = LEAF_STE;
}

#if SECURE_WORLD == 0
static void construct_tlbi_cmd(uint64_t *cmd, struct cmd_tlbi cmd_format)
{
	cmd[0] = COMPOSE(cmd_format.opcode, OP_SHIFT, OP_MASK);
	cmd[1] = 0;
}
#endif

static void construct_cmd_sync(uint64_t *cmd)
{
	cmd[0] = COMPOSE(OP_CMD_SYNC, OP_SHIFT, OP_MASK);
	cmd[0] = cmd[0] | COMPOSE(CSIGNAL_NONE, CSIGNAL_SHIFT, CSIGNAL_MASK);
	cmd[1] = 0;
}

static inline uint32_t find_offset_next_wr_idx(struct smmuv3_driver *smmuv3,
					       uint32_t current_idx,
					       uint32_t prod_wrap)
{
	uint32_t next_idx;
	uint32_t max_idx;
	uint32_t wrap_bit_set;

	max_idx = (1 << smmuv3->prop.cmdq_entries_log2) - 1;
	if (current_idx > max_idx) {
		panic("Prod idx overflow\n");
	}

	if (current_idx < max_idx) {
		next_idx = current_idx + 1;
		return next_idx | prod_wrap;
	}

	/*
	 * If current write index is already at the end, we need to wrap
	 * it around i.e, start from 0 and toggle wrap bit
	 */
	next_idx = 0;
	wrap_bit_set = 1 << smmuv3->prop.cmdq_entries_log2;

	if (prod_wrap == 0) {
		return next_idx | wrap_bit_set;
	}

	return next_idx;
}

static inline void push_entry_to_cmdq(uint64_t *cmdq_entry,
				      const uint64_t *cmd_dword)
{
	dlog_verbose("SMMUv3: Writing command to: %p\n", (void *)cmdq_entry);

	for (unsigned int i = 0; i < CMD_SIZE_DW; i++) {
		cmdq_entry[i] = cmd_dword[i];
	}

	/*
	 * Ensure written data(command) is observable to SMMU by performing DSB
	 */
	dsb(sy);
}

static void update_cmdq_prod(struct smmuv3_driver *smmuv3, uint32_t idx)
{
	dlog_verbose("SMMUv3: updated write to CMDQ-PRODBASE\n");
	mmio_write32(smmuv3->cmd_queue.prod_reg_base, idx);

	if (mmio_read32(smmuv3->cmd_queue.prod_reg_base) != idx) {
		panic("Hardware not updated with write index\n");
	}
}

static void smmuv3_show_cmdq_err(struct smmuv3_driver *smmuv3)
{
	uint32_t cons_reg;
	uint32_t gerror_reg;
	uint32_t gerror_n_reg;
	uint32_t offset;
	uint32_t offset_n;

	offset = find_offset(S_GERROR, GERROR);
	offset_n = find_offset(S_GERRORN, GERRORN);

	/* Check if global error conditions exist */
	gerror_reg = mmio_read32_offset(smmuv3->base_addr, offset);
	gerror_n_reg = mmio_read32_offset(smmuv3->base_addr, offset_n);

	/* check if the bits differ between (S)_GERROR and (S)_GERRORN */
	if ((gerror_reg & SFM_ERR_MASK) != (gerror_n_reg & SFM_ERR_MASK)) {
		dlog_error("SMMUv3: Entered service failure mode\n");
	}

	if ((gerror_reg & CMDQ_ERR_MASK) == (gerror_n_reg & CMDQ_ERR_MASK)) {
		return;
	}

	dlog_verbose("ERROR: SMMU cannnot process commands\n");
	dlog_verbose("GERROR: %x; GERROR_N: %x\n", gerror_reg, gerror_n_reg);
	cons_reg = mmio_read32(smmuv3->cmd_queue.cons_reg_base);

	switch (EXTRACT(cons_reg, CMDQ_ERRORCODE_SHIFT, CMDQ_ERRORCODE_MASK)) {
	case CERROR_NONE:
		break;
	case CERROR_ILL:
		dlog_error("SMMUv3: CMDQ encountered error: CERROR_ILL\n");
		break;
	case CERROR_ABT:
		dlog_error("SMMUv3: CMDQ encountered error: CERROR_ABT\n");
		break;
	case CERROR_ATC_INV_SYNC:
		dlog_error(
			"SMMUv3: CMDQ encountered error: "
			"CERROR_ATC_INV_SYNC\n");
		break;
	default:
		dlog_error("SMMUv3: CMDQ encountered error: UNKNOWN\n");
		break;
	}

	dlog_verbose("Acknowledging error by toggling GERRORN[CMD_ERR] bit\n");

	gerror_n_reg = gerror_n_reg ^ CMDQ_ERR_MASK;
	mmio_write32_offset(smmuv3->base_addr, offset_n, gerror_n_reg);
}

static inline void track_cmdq_idx(struct smmuv3_driver *smmuv3)
{
	(void)smmuv3;
	dlog_verbose("Track CMDQ consumer_idx: %x; producer_idx: %x\n",
		     mmio_read32(smmuv3->cmd_queue.cons_reg_base),
		     mmio_read32(smmuv3->cmd_queue.prod_reg_base));
}

static bool smmuv3_issue_cmd(struct smmuv3_driver *smmuv3, uint64_t *cmd)
{
	uint32_t prod_idx;
	uint32_t cons_idx;
	uint32_t prod_wrap;
	uint32_t cons_wrap;
	uint32_t prod_reg;
	uint32_t cons_reg;
	uint32_t index_mask;
	uint32_t q_max_entries;
	uint32_t q_empty_slots;
	void *cmd_target;
	uint32_t next_wr_idx;
	uint32_t current_wr_idx;

	q_max_entries = 1 << smmuv3->prop.cmdq_entries_log2;
	index_mask = ALL_1s(smmuv3->prop.cmdq_entries_log2);
	prod_reg = mmio_read32(smmuv3->cmd_queue.prod_reg_base);
	prod_wrap =
		EXTRACT(prod_reg, smmuv3->prop.cmdq_entries_log2, WRAP_MASK);
	prod_idx = prod_reg & index_mask;

	cons_reg = mmio_read32(smmuv3->cmd_queue.cons_reg_base);
	cons_wrap =
		EXTRACT(cons_reg, smmuv3->prop.cmdq_entries_log2, WRAP_MASK);
	cons_idx = cons_reg & index_mask;

	smmuv3_show_cmdq_err(smmuv3);

	if (prod_wrap == cons_wrap) {
		q_empty_slots = q_max_entries - (prod_idx - cons_idx);
	} else {
		q_empty_slots = cons_idx - prod_idx;
	}

	if (q_empty_slots == 0) {
		dlog_error(
			"SMMUv3: Command queue full; No cmd can be "
			"issued\n");
		return false;
	}

	current_wr_idx = prod_idx;
	cmd_target = (void *)((uint8_t *)smmuv3->cmd_queue.q_base +
			      current_wr_idx * CMD_SIZE);
	push_entry_to_cmdq((uint64_t *)cmd_target, cmd);

	next_wr_idx = find_offset_next_wr_idx(
		smmuv3, current_wr_idx,
		(prod_wrap << smmuv3->prop.cmdq_entries_log2));

	track_cmdq_idx(smmuv3);
	dlog_verbose("current_wr_idx: %x; next_wr_idx: %x\n", current_wr_idx,
		     next_wr_idx);

	/*
	 * Host(PE) updates the register indicating the next empty space in
	 * queue
	 */
	update_cmdq_prod(smmuv3, next_wr_idx);

	return true;
}

static bool smmuv3_rd_meets_wr_idx(struct smmuv3_driver *smmuv3)
{
	unsigned int attempts;
	uint32_t prod_reg;
	uint32_t cons_reg;
	uint32_t prod_idx;
	uint32_t cons_idx;
	uint32_t prod_wrap;
	uint32_t cons_wrap;
	uint32_t index_mask;

	index_mask = ALL_1s(smmuv3->prop.cmdq_entries_log2);
	prod_reg = mmio_read32(smmuv3->cmd_queue.prod_reg_base);
	prod_wrap =
		EXTRACT(prod_reg, smmuv3->prop.cmdq_entries_log2, WRAP_MASK);
	prod_idx = prod_reg & index_mask;

	cons_reg = mmio_read32(smmuv3->cmd_queue.cons_reg_base);
	cons_wrap =
		EXTRACT(cons_reg, smmuv3->prop.cmdq_entries_log2, WRAP_MASK);
	cons_idx = cons_reg & index_mask;

	attempts = 0;
	while (attempts++ < 100000) {
		if ((cons_wrap == prod_wrap) && (prod_idx == cons_idx)) {
			return true;
		}

		cons_reg = mmio_read32(smmuv3->cmd_queue.cons_reg_base);
		cons_wrap = EXTRACT(cons_reg, smmuv3->prop.cmdq_entries_log2,
				    WRAP_MASK);
		cons_idx = cons_reg & index_mask;
	}

	dlog_error("SMMUv3: Timeout CMDQ; CONS_REG: %x; PROD_REG: %x\n",
		   cons_reg, prod_reg);

	return false;
}

static bool smmuv3_synchronize_cmdq(struct smmuv3_driver *smmuv3)
{
	uint64_t cmd[CMD_SIZE_DW];

	construct_cmd_sync(cmd);

	if (!smmuv3_issue_cmd(smmuv3, cmd)) {
		return false;
	}

	/*
	 * CMD_SYNC waits for completion of all prior commands and ensures
	 * observability of any related transactions through and from the SMMU.
	 * Ensure command queue read(consumer) index catches up with the write
	 * (producer) index.
	 */

	track_cmdq_idx(smmuv3);

	if (!smmuv3_rd_meets_wr_idx(smmuv3)) {
		dlog_error(
			"SMMUv3: Timeout: CMDQ populated by PE not consumed by "
			"SMMU\n");
		return false;
	}

	track_cmdq_idx(smmuv3);

	return true;
}

static bool inval_cached_cfgs(struct smmuv3_driver *smmuv3)
{
	uint64_t cmd[CMD_SIZE_DW];

	/* Invalidate configuration caches */
	construct_inv_all_cfg(cmd);

	if (!smmuv3_issue_cmd(smmuv3, cmd)) {
		dlog_error(
			"SMMUv3: Failed to issue CFGI_ALL command to CMDQ\n");
		return false;
	}

	/*
	 * Issue CMD_SYNC to ensure completion of prior commands used for
	 * invalidation
	 */
	if (!smmuv3_synchronize_cmdq(smmuv3)) {
		dlog_error("SMMUv3: Failed to synchronize\n");
		return false;
	}

	return true;
}

static bool inval_cached_STE(struct smmuv3_driver *smmuv3, uint32_t sid)
{
	uint64_t cmd[CMD_SIZE_DW];

	/* Invalidate configuration related to a STE */
	construct_inv_ste_cfg(cmd, sid);

	if (!smmuv3_issue_cmd(smmuv3, cmd)) {
		dlog_error(
			"SMMUv3: Failed to issue CFGI_STE command to CMDQ\n");
		return false;
	}

	/*
	 * Issue CMD_SYNC to ensure completion of prior commands used for
	 * invalidation
	 */
	if (!smmuv3_synchronize_cmdq(smmuv3)) {
		dlog_error("SMMUv3: Failed to synchronize\n");
		return false;
	}

	return true;
}

static bool smmuv3_inv_cfg_tlbs(struct smmuv3_driver *smmuv3)
{
#if SECURE_WORLD == 1

	/* Set SMMU_S_INIT.INV_ALL to 1 */
	dlog_verbose("SMMUv3: write to S_INIT\n");
	mmio_write32_offset(smmuv3->base_addr, S_INIT, SMMU_INV_ALL);

	/*
	 * Poll to check SMMU_S_INIT.INV_ALL is set to 0 by SMMU to indicate
	 * completion of invalidation
	 */
	if (!smmuv3_poll(smmuv3->base_addr, S_INIT, INV_COMPLETE, 1)) {
		dlog_error(
			"SMMUv3: Could not invalidate configuration caches "
			"using SMMU_S_INIT\n");
		return false;
	}
#else
	uint64_t cmd[CMD_SIZE_DW];

	/* Invalidate all cached configurations */
	if (!inval_cached_cfgs(smmuv3)) {
		return false;
	}

	/* Invalidate TLB entries using:
	 * CMD_TLBI_EL2_ALL and CMD_TLBI_NSNH_ALL
	 */
	struct cmd_tlbi cmd_tlbi_format = {.opcode = OP_TLBI_EL2_ALL};

	construct_tlbi_cmd(cmd, cmd_tlbi_format);

	if (!smmuv3_issue_cmd(smmuv3, cmd)) {
		dlog_error("SMMUv3: Failed to invalidate TLB entries\n");
		return false;
	}

	cmd_tlbi_format.opcode = OP_TLBI_NSNH_ALL;

	construct_tlbi_cmd(cmd, cmd_tlbi_format);

	if (!smmuv3_issue_cmd(smmuv3, cmd)) {
		dlog_error("SMMUv3: Failed to invalidate TLB entries\n");
		return false;
	}
#endif
	return true;
}

/*
 * In stream bypass configuration, following fields are used to apply attributes
 * to the bypass transactions:
 * MTCFG/MemAttr, ALLOCCFG, SHCFG.
 * NSCFG, PRIVCFG, INSTCFG.
 */
static void create_bypass_ste(uint64_t *ste)
{
	ste[0] = STE_VALID;
	ste[0] |= COMPOSE(STE_CFG_BYPASS, STE_CFG_SHIFT, STE_CFG_MASK);
	ste[1] = COMPOSE(USE_INCOMING_ATTR, STE_MTCFG_SHIFT, STE_MTCFG_MASK);
	ste[1] |= COMPOSE(USE_INCOMING_ATTR, STE_ALLOCCFG_SHIFT,
			  STE_ALLOCCFG_MASK);
	ste[1] |=
		COMPOSE(USE_INCOMING_SH_ATTR, STE_SHCFG_SHIFT, STE_SHCFG_MASK);
	ste[1] |= COMPOSE(USE_INCOMING_ATTR, STE_NSCFG_SHIFT, STE_NSCFG_MASK);
	ste[1] |=
		COMPOSE(USE_INCOMING_ATTR, STE_PRIVCFG_SHIFT, STE_PRIVCFG_MASK);
	ste[1] |=
		COMPOSE(USE_INCOMING_ATTR, STE_INSTCFG_SHIFT, STE_INSTCFG_MASK);
	ste[2] = 0;
	ste[3] = 0;
	ste[4] = 0;
	ste[5] = 0;
	ste[6] = 0;
	ste[7] = 0;
}

/*
 * Control the default translation behaviour of SMMU for incoming streams when
 * it is enabled. The behaviour is controlled by the stream table entries. The
 * default response is to bypass the incoming transactions and use incoming
 * attributes.
 */
static void smmuv3_default_translation(struct smmuv3_driver *smmuv3)
{
	unsigned int i;
	unsigned int ste_count;

	/* Each stream table entry is 64 bytes wide i.e., 8 Double Words*/
	uint64_t ste_data[STE_SIZE_DW];
	uint64_t *ste_addr;

	ste_count = (1 << smmuv3->prop.stream_n_bits);

	create_bypass_ste(ste_data);
	ste_addr = (uint64_t *)smmuv3->strtab_cfg.base;

	/* Populate all stream table entries */
	for (i = 0; i < ste_count; i++) {
		write_ste(ste_addr, ste_data);
		ste_addr += STE_SIZE_DW;
	}

	/*
	 * Note 1:
	 * Spec says after an SMMU configuration structure, such as STE, is
	 * altered in any way, an invalidation command must be issued to ensure
	 * any cached copies of stale configuration are discarded.
	 */
	if (!inval_cached_cfgs(smmuv3)) {
		panic("SMMUv3: Unable to invalidate config caches\n");
	}
}

static bool smmuv3_enable_init(struct smmuv3_driver *smmuv3)
{
	uint32_t offset_cr0;
	uint32_t offset_cr0_ack;
	uint32_t data_cr0;

	offset_cr0 = find_offset(S_CR0, CR0);
	offset_cr0_ack = find_offset(S_CR0_ACK, CR0_ACK);

	track_cmdq_idx(smmuv3);

	/* Enable Command queue */
	data_cr0 = mmio_read32_offset(smmuv3->base_addr, offset_cr0);
	data_cr0 = data_cr0 | CMDQEN_MASK;

	dlog_verbose("SMMUv3: write to (S_)CR0\n");
	mmio_write32_offset(smmuv3->base_addr, offset_cr0, data_cr0);

	/* Poll SMMU_(S_)CR0ACK */
	if (!smmuv3_poll(smmuv3->base_addr, offset_cr0_ack, data_cr0,
			 CMDQEN_MASK)) {
		dlog_error(
			"SMMUv3: Failed to enable command queue processing\n");
		return false;
	}

	/* Enable event queue */
	data_cr0 = data_cr0 | EVTQEN_MASK;
	mmio_write32_offset(smmuv3->base_addr, offset_cr0, data_cr0);

	if (!smmuv3_poll(smmuv3->base_addr, offset_cr0_ack, data_cr0,
			 EVTQEN_MASK)) {
		dlog_error("SMMUv3: Failed to enable event queue\n");
		return false;
	}

	/* Invalidate cached configurations and TLBs */
	if (!smmuv3_inv_cfg_tlbs(smmuv3)) {
		return false;
	}

	smmuv3_default_translation(smmuv3);

	/* Enable SMMU translation */
	data_cr0 = data_cr0 | SMMU_ENABLE;
	mmio_write32_offset(smmuv3->base_addr, offset_cr0, data_cr0);

	if (!smmuv3_poll(smmuv3->base_addr, offset_cr0_ack, data_cr0,
			 SMMUEN_MASK)) {
		dlog_error(
			"SMMUv3: Failed to enable SMMU for performing "
			"translations\n");
		return false;
	}

	track_cmdq_idx(smmuv3);
	return true;
}

bool smmuv3_driver_init(struct smmuv3_driver *smmuv3, uintpaddr_t base,
			struct mm_stage1_locked stage1_locked,
			struct mpool *ppool)
{
	void *base_addr;

	base_addr = mm_identity_map(stage1_locked, pa_init(base),
				    pa_init(base + SMMUv3_MEM_SIZE),
				    MM_MODE_R | MM_MODE_W | MM_MODE_D, ppool);
	if (base_addr == NULL) {
		dlog_error(
			"SMMUv3: Could not map SMMU into Hafnium memory map\n");
		return false;
	}

	dlog_verbose("SMMUv3 mapped at %p\n", base_addr);
	smmuv3->base_addr = base_addr;
	smmuv3->smmu_id = smmu_instance;
	smmu_instance++;

	if (!smmuv3_reset(smmuv3)) {
		return false;
	}

	if (!smmuv3_identify_features(smmuv3)) {
		return false;
	}

	if (!smmuv3_xlat_support(smmuv3)) {
		return false;
	}

	if (!smmuv3_configure_queues(smmuv3, ppool)) {
		return false;
	}

	if (!smmuv3_configure_str_table(smmuv3, ppool)) {
		return false;
	}

	if (!smmuv3_enable_init(smmuv3)) {
		return false;
	}

	return true;
}

static bool smmuv3_config_ste_stg2(struct smmuv3_driver *smmuv3, uint16_t vm_id,
				   uint64_t *ste_data,
				   struct mm_ptable *iommu_ptable,
				   struct mm_ptable *iommu_ptable_ns,
				   uint8_t dma_device_id)
{
	unsigned int pa_bits;
	uint64_t sl0;
	uint64_t s2_ps_bits;
	uint64_t vttbr;

	s2_ps_bits = smmuv3->prop.oas_encoding;
	pa_bits = smmuv3->prop.oas;

	/*
	 * Determine sl0, starting level of the page table, based on the number
	 * of bits.
	 *
	 *  - 0 => start at level 1
	 *  - 1 => start at level 2
	 *  - 2 => start at level 3
	 */
	if (pa_bits >= 44) {
		sl0 = 2;
	} else if (pa_bits >= 35) {
		sl0 = 1;
	} else {
		sl0 = 0;
	}

	/* The following fields have to be programmed for Stage 2 translation:
	 * Fields common to Secure and Non-Secure STE
	Bits		Name		Description
	------------------------------------------------------------------------
	178:176		S2PS		PA size of stg2 PA range
	179		S2AA64		Select between AArch32 or AArch64 format
	180		S2ENDI		Endianness for stg2 translation tables
	181		S2AFFD		Disable access flag for stg2 translation
	167:166		S2SL0		Starting level of stg2 translation table
					walk
	169:168		S2IR0		Stg2 Inner region cachebility
	171:170		S2OR0		Stg2 Outer region cachebility
	173:172		S2SH0		Shareability
	143:128		S2VMID		VMID associated with current translation
	182		S2PTW		Protected Table Walk
	243:196		S2TTB		Stg2 translation table base address
	165:160		S2T0SZ		Size of IPA input region covered by stg2
	175:174		S2TG		Translation granularity

	  * Fields specific to Secure STE
	Bits		Name		Description
	------------------------------------------------------------------------
	192		S2NSW		NS bit used for all stg2 translation
					table walks for secure stream Non-secure
					IPA space
	193		S2NSA		NS bit output for all stg2 secure stream
					non-secure IPA translations
	435:388		S_S2TTB		Secure Stg2 TTB
	293:288		S_S2T0SZ	Secure version of S2T0SZ
	303:302		S_S2TG		Secure version of S2TG
	384		S2SW		NS bit used for all stg2 translation
					table walks for Secure IPA space
	385		S2SA		NS bit output for all stg2 Secure IPA
					translations

	*/
	/* BITS 63:0 */
	ste_data[0] =
		STE_VALID | COMPOSE(STE_CFG_STG2, STE_CFG_SHIFT, STE_CFG_MASK);

	/* BITS 191:128 */
	ste_data[2] = COMPOSE(vm_id, STE_VMID_SHIFT, STE_VMID_MASK);
	ste_data[2] |= COMPOSE(64 - smmuv3->prop.ias, STE_S2T0SZ_SHIFT,
			       STE_S2T0SZ_MASK);
	ste_data[2] |= COMPOSE(sl0, STE_S2SL0_SHIFT, STE_S2SL0_MASK);
	ste_data[2] |= COMPOSE(WB_CACHEABLE, STE_S2IR0_SHIFT, STE_S2IR0_MASK);
	ste_data[2] |= COMPOSE(WB_CACHEABLE, STE_S2OR0_SHIFT, STE_S2OR0_MASK);
	ste_data[2] |=
		COMPOSE(INNER_SHAREABLE, STE_S2SH0_SHIFT, STE_S2SH0_MASK);
	ste_data[2] |= COMPOSE(S2TF_4KB, STE_S2TG_SHIFT, STE_S2TG_MASK);
	ste_data[2] |= COMPOSE(s2_ps_bits, STE_S2PS_SHIFT, STE_S2PS_MASK);
	ste_data[2] |= COMPOSE(S2AA64, STE_S2AA64_SHIFT, STE_S2AA64_MASK);
	ste_data[2] |=
		COMPOSE(S2_LITTLEENDIAN, STE_S2ENDI_SHIFT, STE_S2ENDI_MASK);
	ste_data[2] |= COMPOSE(AF_DISABLED, STE_S2AFFD_SHIFT, STE_S2AFFD_MASK);
	ste_data[2] |=
		COMPOSE(PTW_DEVICE_FAULT, STE_S2PTW_SHIFT, STE_S2PTW_MASK);
	ste_data[2] |= COMPOSE(0ULL, STE_S2RS_SHIFT, STE_S2RS_MASK);

	/* Refer to function arch_mm_init() in src/arch/aarch64/mm.c for
	 * explanation of the choice of NSA, NSW, SA and SW fields in secure
	 * state. NSA = 1 : NSW = 0 : SA =  0 : SW =  0 :
	 */
#if SECURE_WORLD == 1
	uint64_t vsttbr;

	/* BITS 243:196 */
	vttbr = (pa_addr(iommu_ptable_ns[dma_device_id].root) &
		 GEN_MASK(51, 4)) >>
		4;

	/* BITS 435:388 */
	vsttbr =
		(pa_addr(iommu_ptable[dma_device_id].root) & GEN_MASK(51, 4)) >>
		4;

	/* STRW is S-EL2*/
	ste_data[1] = COMPOSE(STW_SEL2, STE_STW_SHIFT, STE_STW_MASK);
	ste_data[3] = COMPOSE(0, STE_S2NSW_SHIFT, STE_S2NSW_MASK);
	ste_data[3] |= COMPOSE(1, STE_S2NSA_SHIFT, STE_S2NSA_MASK);

	/* BITS 319:256 */
	ste_data[4] = COMPOSE(64 - smmuv3->prop.ias, STE_SS2T0SZ_SHIFT,
			      STE_SS2T0SZ_MASK);
	ste_data[4] |= COMPOSE(sl0, STE_SS2SL0_SHIFT, STE_SS2SL0_MASK);
	ste_data[4] |= COMPOSE(S2TF_4KB, STE_SS2TG_SHIFT, STE_SS2TG_MASK);

	/* BITS 447:384 */
	ste_data[6] = COMPOSE(0, STE_S2SW_SHIFT, STE_S2SW_MASK);
	ste_data[6] |= COMPOSE(0, STE_S2SA_SHIFT, STE_S2SA_MASK);
	ste_data[6] |= COMPOSE(vsttbr, STE_SS2TTB_SHIFT, STE_SS2TTB_MASK);
#else
	(void)iommu_ptable_ns;

	/* BITS 243:196 */
	vttbr = (pa_addr(iommu_ptable[dma_device_id].root) & GEN_MASK(51, 4)) >>
		4;

	/* STRW is EL2*/
	ste_data[1] = COMPOSE(STW_EL2, STE_STW_SHIFT, STE_STW_MASK);
#endif
	ste_data[3] |= COMPOSE(vttbr, STE_S2TTB_SHIFT, STE_S2TTB_MASK);

	return true;
}

static bool smmuv3_configure_stream(struct smmuv3_driver *smmuv3,
				    uint16_t vm_id, uint32_t sid,
				    struct mm_ptable *iommu_ptable,
				    struct mm_ptable *iommu_ptable_ns,
				    uint8_t dma_device_id)
{
	track_cmdq_idx(smmuv3);

	/* Each stream table entry is 64 bytes wide i.e., 8 Double Words*/
	uint64_t ste_data[STE_SIZE_DW];
	uint64_t *ste_addr;
	uint32_t max_sid;

	max_sid = (1 << smmuv3->prop.stream_n_bits) - 1;

	if (sid > max_sid) {
		dlog_error("SMMUv3: Illegal streamID specified: %u\n", sid);
		return false;
	}

	/* Refer Note 1 */
	if (!inval_cached_STE(smmuv3, sid)) {
		return false;
	}

	clear_ste(ste_data);
	if (!smmuv3_config_ste_stg2(smmuv3, vm_id, ste_data, iommu_ptable,
				    iommu_ptable_ns, dma_device_id)) {
		return false;
	}

	/* StreamID serves as an index into Stream Table */
	ste_addr = (uint64_t *)smmuv3->strtab_cfg.base + sid * STE_SIZE_DW;
	write_ste(ste_addr, ste_data);

	/* Refer Note 1 */
	if (!inval_cached_STE(smmuv3, sid)) {
		return false;
	}

	track_cmdq_idx(smmuv3);

	return true;
}

bool plat_iommu_init(const struct fdt *fdt,
		     struct mm_stage1_locked stage1_locked, struct mpool *ppool)
{
	(void)fdt;

	if (!smmuv3_driver_init(&arm_smmuv3, SMMUv3_BASE, stage1_locked,
				ppool)) {
		dlog_error("SMMUv3: Failed to initialize driver\n");
		return false;
	}

	dlog_info("Arm SMMUv3 initialized\n");

	return true;
}

bool plat_iommu_unmap_iommus(struct vm_locked vm_locked, struct mpool *ppool)
{
	(void)vm_locked;
	(void)ppool;

	return true;
}

void plat_iommu_identity_map(struct vm_locked vm_locked, paddr_t begin,
			     paddr_t end, uint32_t mode)
{
	(void)vm_locked;
	(void)begin;
	(void)end;
	(void)mode;
}

bool plat_iommu_attach_peripheral(struct mm_stage1_locked stage1_locked,
				  struct vm_locked vm_locked,
				  const struct manifest_vm *manifest_vm,
				  struct mpool *ppool)
{
	(void)stage1_locked;
	(void)ppool;

	unsigned int i;
	unsigned int j;

	struct dma_device_properties upstream_peripheral;
	uint16_t vm_id;
	struct mm_ptable *iommu_ptable;
	struct mm_ptable *iommu_ptable_ns;

	vm_id = vm_locked.vm->id;
	iommu_ptable = vm_locked.vm->iommu_ptables;

#if SECURE_WORLD == 1
	iommu_ptable_ns = vm_locked.vm->arch.iommu_ptables_ns;
#else
	iommu_ptable_ns = NULL;
#endif

	/*
	 * No support to enforce access control through (stage 1) address
	 * translation for memory accesses by DMA device on behalf of an
	 * EL0/S-EL0 partition.
	 */
	if (vm_locked.vm->el0_partition) {
		return true;
	}

	/* Iterate through device region nodes described in vm manifest */
	for (i = 0; i < manifest_vm->partition.dev_region_count; i++) {
		upstream_peripheral =
			manifest_vm->partition.dev_regions[i].dma_prop;

		if (upstream_peripheral.smmu_id != MANIFEST_INVALID_ID &&
		    upstream_peripheral.smmu_id != arm_smmuv3.smmu_id) {
			dlog_warning(
				"SMMUv3: Unexpected smmu-id:%u specified "
				"in manifest\n",
				upstream_peripheral.smmu_id);
			continue;
		}

		if (upstream_peripheral.smmu_id != MANIFEST_INVALID_ID) {
			/*
			 * A peripheral that is upstream of an SMMU IP will have
			 * a valid smmu_id property in the device_region node
			 * described in the partition manifest. Such a
			 * node(peripheral) must have a non-zero list of stream
			 * IDs.
			 */

			if (upstream_peripheral.stream_count == 0) {
				dlog_error(
					"SMMUv3: Count of valid stream IDs "
					"cannot be 0\n");
				return false;
			}
		}

		if (upstream_peripheral.stream_count >
		    (1 << arm_smmuv3.prop.stream_n_bits)) {
			dlog_error(
				"SMMUv3: Count of stream IDs exceeds the "
				"limit of %u\n",
				(1 << arm_smmuv3.prop.stream_n_bits));
			return false;
		}

		dlog_verbose("stream_count of upstream peripheral device: %u\n",
			     upstream_peripheral.stream_count);

		for (j = 0; j < upstream_peripheral.stream_count; j++) {
			if (!smmuv3_configure_stream(
				    &arm_smmuv3, vm_id,
				    upstream_peripheral.stream_ids[j],
				    iommu_ptable, iommu_ptable_ns,
				    upstream_peripheral.dma_device_id)) {
				dlog_error(
					"SMMUv3: Could not configure "
					"streamID: %u",
					j);
				return false;
			}
		}
	}

	return true;
}
