/*
 * Copyright 2020 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/mmio.h"
#include "hf/plat/iommu.h"

#define EXTRACT(data, shift, mask) (((data) >> (shift)) & (mask))
#define ALL_1s(n) ((1ULL << (n)) - 1)
#define GEN_MASK(MSB, LSB) ((ALL_1s((MSB) - (LSB) + 1)) << (LSB))
#define COMPOSE(value, shift, mask) (((value) & (mask)) << (shift))

/* Offset of SMMUv3 registers */
#define IDR0 0x0
#define IDR1 0x4
#define GBPA 0x44
#define GERROR 0x60
#define GERRORN 0x64
#define IDR5 0x014
#define AIDR 0x01c
#define CR0 0x020
#define CR0_ACK 0x024
#define CR1 0x028
#define CR2 0x02c
#define STRTAB_BASE 0x080
#define STRTAB_BASE_CFG 0x088
#define CMDQ_BASE 0x090
#define CMDQ_PROD 0x098
#define CMDQ_CONS 0x09c
#define EVTQ_BASE 0x0a0
#define EVTQ_PROD 0x100a8
#define EVTQ_CONS 0x100ac

#define S_IDR0 0x8000
#define S_IDR1 0x8004
#define S_CR0 0x8020
#define S_GBPA 0x8044
#define S_GERROR 0x8060
#define S_GERRORN 0x8064
#define S_CR1 0x8028
#define S_CR2 0x802c
#define S_CR0_ACK 0x8024
#define S_INIT 0x803c
#define S_STRTAB_BASE 0x8080
#define S_STRTAB_BASE_CFG 0x8088
#define S_CMDQ_BASE 0x8090
#define S_CMDQ_PROD 0x8098
#define S_CMDQ_CONS 0x809c
#define S_EVTQ_BASE 0x80a0
#define S_EVTQ_PROD 0x80a8
#define S_EVTQ_CONS 0x80ac

#define ARCH_REV_SHIFT 0
#define ARCH_REV_MASK 0xFF
#define ST_LEVEL_SHIFT (27)
#define ST_LEVEL_MASK (3)
#define TTENDIAN_SHIFT (21)
#define TTENDIAN_MASK (3)
#define BTM_SHIFT (5)
#define BTM_MASK (1)
#define TTF_SHIFT (2)
#define TTF_MASK (3)
#define XLAT_STG_SHIFT (0)
#define XLAT_STG_MASK (3)
#define PRESET_SHIFT (29)
#define PRESET_MASK (3)
#define CMDQS_SHIFT (21)
#define CMDQS_MASK (0x1F)
#define EVTQS_SHIFT (16)
#define EVTQS_MASK (0x1F)
#define SUB_SID_SHIFT (6)
#define SUB_SID_SIZE_MASK (0x1F)
#define SID_SHIFT (0)
#define SID_SIZE_MASK (0x3F)
#define OAS_SHIFT (0)
#define OAS_MASK (7)
#define RA_HINT_SHIFT (62)
#define WA_HINT_SHIFT (62)
#define STR_FMT_SHIFT (16)
#define WRAP_MASK (1)

/* Command Error codes and fields */
#define CMDQ_ERRORCODE_SHIFT (24)
#define CMDQ_ERRORCODE_MASK (0x7F)
#define CERROR_NONE 0
#define CERROR_ILL 1
#define CERROR_ABT 2
#define CERROR_ATC_INV_SYNC 3

/* Bit fields related to command format */
#define OP_SHIFT (0)
#define OP_MASK (0xFF)
#define SSEC_SHIFT (10)
#define SSEC_MASK (1)
#define CMD_SID_SHIFT 32
#define CMD_SID_MASK (0xFFFFFFFF)
#define SID_ALL (0x1F)
#define SID_RANGE_SHIFT (0)
#define SID_RANGE_MASK (0x1F)
#define LEAF_STE (1)
#define S_STREAM (1)
#define NS_STREAM (0)

/* Completion Signal */
#define CSIGNAL_NONE (0)
#define CSIGNAL_SHIFT 12
#define CSIGNAL_MASK (0x3)

/* Command opcodes */
#define OP_CFGI_ALL 0x04
#define OP_CFGI_STE 0x03
#define OP_TLBI_EL2_ALL 0x20
#define OP_TLBI_NSNH_ALL 0x30
#define OP_CMD_SYNC 0x46
#define OP_TLBI_SEL2_ALL 0x50

#define LINEAR_STR_TABLE 0
#define TWO_LVL_STR_TABLE 1
#define MIX_ENDIAN 0
#define RES_ENDIAN 1
#define LIT_ENDIAN 2
#define BIG_ENDIAN 3
#define RES_TTF 0
#define AARCH32_TTF 1
#define AARCH64_TTF 2
#define AARCH32_64_TTF 3
#define NO_STG1_STG2 0
#define STG1_ONLY 2
#define STG2_ONLY 1
#define STG1_STG2 3
#define CMDQS_MAX 19
#define EVTQS_MAX 19
#define SUB_SID_SIZE_MAX 20
#define SID_SIZE_MAX 32
#define OAS_32BITS 0
#define OAS_36BITS 1
#define OAS_40BITS 2
#define OAS_42BITS 3
#define OAS_44BITS 4
#define OAS_48BITS 5
#define OAS_52BITS 6
#define OAS_RES 7
#define PTM_ENABLE 0

#define SECURE_IMPL_MASK (1 << 31)
#define SEL2_STG2_SUPPORT (1 << 29)
#define CMDQEN_MASK (1 << 3)
#define EVTQEN_MASK (1 << 2)
#define SMMUEN_MASK (1 << 0)
#define SMMU_ENABLE (1 << 0)
#define SMMUEN_CLR_MASK (0xFFFFFFFE)
#define SMMU_INV_ALL (1 << 0)
#define INV_COMPLETE 0
#define PTM_SHIFT 2
#define PTM_MASK 1

#define CMD_SIZE ((size_t)(16))
#define CMD_SIZE_DW ((size_t)(CMD_SIZE / 8))
#define EVT_RECORD_SIZE 32
#define STE_SIZE 64
#define STE_SIZE_DW ((size_t)(STE_SIZE / 8))

/* Global ByPass Attribute fields */
#define BYPASS_GBPA 0
#define INCOMING_CFG 0
#define UPDATE_SHIFT 31
#define UPDATE_MASK 0x1
#define ABORT_SHIFT 20
#define ABORT_MASK 0x1
#define INSTCFG_SHIFT 18
#define INSTCFG_MASK 0x3
#define PRIVCFG_SHIFT 16
#define PRIVCFG_MASK 0x3
#define SHCFG_SHIFT 12
#define SHCFG_MASK 0x3
#define ALLOCFG_SHIFT 8
#define ALLOCFG_MASK 0xF
#define MTCFG_SHIFT 4
#define MTCFG_MASK 0x1

/* Global Error register fields */
#define SFM_ERR_MASK (1 << 8)
#define CMDQ_ERR_MASK (1 << 0)

/* Stream Table Entry fields */
#define STE_VALID 1ULL
#define STE_CFG_BYPASS 4ULL
#define STE_CFG_STG2 6ULL
#define STW_SEL2 2ULL
#define STW_EL2 2ULL
#define USE_INCOMING_ATTR 0ULL
#define USE_INCOMING_SH_ATTR 1ULL
#define WB_CACHEABLE 1ULL
#define INNER_SHAREABLE 3ULL
#define S2TF_4KB 0ULL
#define S2AA64 1ULL
#define S2_LITTLEENDIAN 0ULL
#define AF_DISABLED 1ULL
#define PTW_DEVICE_FAULT 1ULL

#define WRAP_1DW 64
#define WRAP_2DW 128
#define WRAP_3DW 192
#define WRAP_4DW 256
#define WRAP_6DW 384
#define STE_CFG_SHIFT 1
#define STE_CFG_MASK 0x7
#define STE_STW_SHIFT (94 - WRAP_1DW)
#define STE_STW_MASK 0x3
#define STE_MTCFG_SHIFT (100 - WRAP_1DW)
#define STE_MTCFG_MASK 0x1
#define STE_ALLOCCFG_SHIFT (101 - WRAP_1DW)
#define STE_ALLOCCFG_MASK 0xF
#define STE_SHCFG_SHIFT (108 - WRAP_1DW)
#define STE_SHCFG_MASK 0x3
#define STE_NSCFG_SHIFT (110 - WRAP_1DW)
#define STE_NSCFG_MASK 0x3
#define STE_PRIVCFG_SHIFT (112 - WRAP_1DW)
#define STE_PRIVCFG_MASK 0x3
#define STE_INSTCFG_SHIFT (114 - WRAP_1DW)
#define STE_INSTCFG_MASK 0x3
#define STE_VMID_SHIFT (128 - WRAP_2DW)
#define STE_VMID_MASK 0xffff
#define STE_S2T0SZ_SHIFT (160 - WRAP_2DW)
#define STE_S2T0SZ_MASK 0x3f
#define STE_S2SL0_SHIFT (166 - WRAP_2DW)
#define STE_S2SL0_MASK 0x3
#define STE_S2IR0_SHIFT (168 - WRAP_2DW)
#define STE_S2IR0_MASK 0x3
#define STE_S2OR0_SHIFT (170 - WRAP_2DW)
#define STE_S2OR0_MASK 0x3
#define STE_S2SH0_SHIFT (172 - WRAP_2DW)
#define STE_S2SH0_MASK 0x3
#define STE_S2TG_SHIFT (174 - WRAP_2DW)
#define STE_S2TG_MASK 0x3
#define STE_S2PS_SHIFT (176 - WRAP_2DW)
#define STE_S2PS_MASK 0x7
#define STE_S2AA64_SHIFT (179 - WRAP_2DW)
#define STE_S2AA64_MASK 0x1
#define STE_S2ENDI_SHIFT (180 - WRAP_2DW)
#define STE_S2ENDI_MASK 0x1
#define STE_S2AFFD_SHIFT (181 - WRAP_2DW)
#define STE_S2AFFD_MASK 0x1
#define STE_S2PTW_SHIFT (182 - WRAP_2DW)
#define STE_S2PTW_MASK 0x1
#define STE_S2RS_SHIFT (185 - WRAP_2DW)
#define STE_S2RS_MASK 0x3
#define STE_S2NSW_SHIFT (192 - WRAP_3DW)
#define STE_S2NSW_MASK 0x1
#define STE_S2NSA_SHIFT (193 - WRAP_3DW)
#define STE_S2NSA_MASK 0x1
#define STE_S2TTB_SHIFT (196 - WRAP_3DW)
#define STE_S2TTB_MASK ALL_1s(48)

#define STE_SS2T0SZ_SHIFT (288 - WRAP_4DW)
#define STE_SS2T0SZ_MASK 0x3f
#define STE_SS2SL0_SHIFT (294 - WRAP_4DW)
#define STE_SS2SL0_MASK 0x3
#define STE_SS2TG_SHIFT (302 - WRAP_4DW)
#define STE_SS2TG_MASK 0x3
#define STE_S2SW_SHIFT (384 - WRAP_6DW)
#define STE_S2SW_MASK 0x1
#define STE_S2SA_SHIFT (385 - WRAP_6DW)
#define STE_S2SA_MASK 0x1
#define STE_SS2TTB_SHIFT (388 - WRAP_6DW)
#define STE_SS2TTB_MASK ALL_1s(48)

/* SMMU_(S)_CR1 attributes and fields */
#define CR1_INSH 3
#define CR1_WBCACHE 1

#define TAB_SH_SHIFT 10
#define TAB_OC_SHIFT 8
#define TAB_IC_SHIFT 6
#define QUE_SH_SHIFT 4
#define QUE_OC_SHIFT 2
#define QUE_IC_SHIFT 0
#define SH_MASK 0x3
#define OC_MASK 0x3
#define IC_MASK 0x3

struct cmd_tlbi {
	uint8_t opcode;
};

struct smmuv3_context_desc {
	uint32_t temp;
};

struct smmuv3_stream_table_config {
	void *base;
};

struct smmuv3_queue {
	void *q_base;
	uint32_t rd_idx, wr_idx;
	uint32_t q_entries;
	void *cons_reg_base;
	void *prod_reg_base;
};

struct smmuv3_features {
	bool linear_str_table;
	bool lvl2_str_table;
	uint32_t endian;
	bool broadcast_TLB;
	uint32_t xlat_format;
	uint32_t xlat_stages;
	uint32_t cmdq_entries_log2;
	uint32_t evtq_entries_log2;
	uint32_t sub_stream_n_bits;
	uint32_t stream_n_bits;
	uint64_t ias;
	uint64_t oas;
	uint32_t oas_encoding;
	uint32_t minor_version;
};

struct smmuv3_driver {
	void *base_addr;
	uint32_t smmu_id;
	struct smmuv3_features prop;
	struct smmuv3_queue cmd_queue;
	struct smmuv3_queue evt_queue;
	struct smmuv3_stream_table_config strtab_cfg;
};
