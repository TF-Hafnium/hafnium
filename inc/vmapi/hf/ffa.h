/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "hf/types.h"

/**
 * The version number of a Firmware Framework implementation is a 31-bit
 * unsigned integer, with the upper 15 bits denoting the major revision,
 * and the lower 16 bits denoting the minor revision.
 *
 * See FF-A specification v1.2 ALP1, section 13.2.1.
 */
enum ffa_version {
	FFA_VERSION_1_0 = 0x10000,
	FFA_VERSION_1_1 = 0x10001,
	FFA_VERSION_1_2 = 0x10002,
	FFA_VERSION_COMPILED = FFA_VERSION_1_2,
};

#define FFA_VERSION_MBZ_BIT (1U << 31U)
#define FFA_VERSION_MAJOR_SHIFT (16U)
#define FFA_VERSION_MAJOR_MASK (0x7FFFU)
#define FFA_VERSION_MINOR_SHIFT (0U)
#define FFA_VERSION_MINOR_MASK (0xFFFFU)

/** Return true if the version is valid (i.e. bit 31 is 0). */
static inline bool ffa_version_is_valid(uint32_t version)
{
	return (version & FFA_VERSION_MBZ_BIT) == 0;
}

/** Construct a version from a pair of major and minor components. */
static inline enum ffa_version make_ffa_version(uint16_t major, uint16_t minor)
{
	return (enum ffa_version)((major << FFA_VERSION_MAJOR_SHIFT) |
				  (minor << FFA_VERSION_MINOR_SHIFT));
}

/** Get the major component of the version. */
static inline uint16_t ffa_version_get_major(enum ffa_version version)
{
	return (version >> FFA_VERSION_MAJOR_SHIFT) & FFA_VERSION_MAJOR_MASK;
}

/** Get the minor component of the version. */
static inline uint16_t ffa_version_get_minor(enum ffa_version version)
{
	return (version >> FFA_VERSION_MINOR_SHIFT) & FFA_VERSION_MINOR_MASK;
}

/**
 * Check major versions are equal and the minor version of the caller is
 * less than or equal to the minor version of the callee.
 */
static inline bool ffa_versions_are_compatible(enum ffa_version caller,
					       enum ffa_version callee)
{
	return ffa_version_get_major(caller) == ffa_version_get_major(callee) &&
	       ffa_version_get_minor(caller) <= ffa_version_get_minor(callee);
}

/* clang-format off */

#define FFA_LOW_32_ID  0x84000060
#define FFA_HIGH_32_ID 0x8400007F
#define FFA_LOW_64_ID  0xC4000060
#define FFA_HIGH_64_ID 0xC400007F

/**
 * FF-A function identifiers.
 * Don't forget to update `ffa_func_name` if you add a new one.
 */
#define FFA_ERROR_32                        0x84000060
#define FFA_SUCCESS_32                      0x84000061
#define FFA_SUCCESS_64                      0xC4000061
#define FFA_INTERRUPT_32                    0x84000062
#define FFA_VERSION_32                      0x84000063
#define FFA_FEATURES_32                     0x84000064
#define FFA_RX_RELEASE_32                   0x84000065
#define FFA_RXTX_MAP_32                     0x84000066
#define FFA_RXTX_MAP_64                     0xC4000066
#define FFA_RXTX_UNMAP_32                   0x84000067
#define FFA_PARTITION_INFO_GET_32           0x84000068
#define FFA_ID_GET_32                       0x84000069
#define FFA_MSG_POLL_32                     0x8400006A /* Legacy FF-A v1.0 */
#define FFA_MSG_WAIT_32                     0x8400006B
#define FFA_YIELD_32                        0x8400006C
#define FFA_RUN_32                          0x8400006D
#define FFA_MSG_SEND_32                     0x8400006E /* Legacy FF-A v1.0 */
#define FFA_MSG_SEND_DIRECT_REQ_32          0x8400006F
#define FFA_MSG_SEND_DIRECT_REQ_64          0xC400006F
#define FFA_MSG_SEND_DIRECT_RESP_32         0x84000070
#define FFA_MSG_SEND_DIRECT_RESP_64         0xC4000070
#define FFA_MEM_DONATE_32                   0x84000071
#define FFA_MEM_DONATE_64                   0xC4000071
#define FFA_MEM_LEND_32                     0x84000072
#define FFA_MEM_LEND_64                     0xC4000072
#define FFA_MEM_SHARE_32                    0x84000073
#define FFA_MEM_SHARE_64                    0xC4000073
#define FFA_MEM_RETRIEVE_REQ_32             0x84000074
#define FFA_MEM_RETRIEVE_REQ_64             0xC4000074
#define FFA_MEM_RETRIEVE_RESP_32            0x84000075
#define FFA_MEM_RELINQUISH_32               0x84000076
#define FFA_MEM_RECLAIM_32                  0x84000077
#define FFA_MEM_FRAG_RX_32                  0x8400007A
#define FFA_MEM_FRAG_TX_32                  0x8400007B
#define FFA_NORMAL_WORLD_RESUME             0x8400007C

/* FF-A v1.1 */
#define FFA_NOTIFICATION_BITMAP_CREATE_32   0x8400007D
#define FFA_NOTIFICATION_BITMAP_DESTROY_32  0x8400007E
#define FFA_NOTIFICATION_BIND_32            0x8400007F
#define FFA_NOTIFICATION_UNBIND_32          0x84000080
#define FFA_NOTIFICATION_SET_32             0x84000081
#define FFA_NOTIFICATION_GET_32             0x84000082
#define FFA_NOTIFICATION_INFO_GET_64        0xC4000083
#define FFA_RX_ACQUIRE_32                   0x84000084
#define FFA_SPM_ID_GET_32                   0x84000085
#define FFA_MSG_SEND2_32                    0x84000086
#define FFA_SECONDARY_EP_REGISTER_64        0xC4000087
#define FFA_MEM_PERM_GET_32                 0x84000088
#define FFA_MEM_PERM_SET_32                 0x84000089
#define FFA_MEM_PERM_GET_64                 0xC4000088
#define FFA_MEM_PERM_SET_64                 0xC4000089

/* FF-A v1.2 */
#define FFA_CONSOLE_LOG_32                  0x8400008A
#define FFA_CONSOLE_LOG_64                  0xC400008A
#define FFA_PARTITION_INFO_GET_REGS_64      0xC400008B
#define FFA_EL3_INTR_HANDLE_32              0x8400008C
#define FFA_MSG_SEND_DIRECT_REQ2_64	    0xC400008D
#define FFA_MSG_SEND_DIRECT_RESP2_64        0xC400008E

/**
 * FF-A error codes.
 * Don't forget to update `ffa_error_name` if you add a new one.
 */
enum ffa_error {
	FFA_NOT_SUPPORTED      = -1,
	FFA_INVALID_PARAMETERS = -2,
	FFA_NO_MEMORY          = -3,
	FFA_BUSY               = -4,
	FFA_INTERRUPTED        = -5,
	FFA_DENIED             = -6,
	FFA_RETRY              = -7,
	FFA_ABORTED            = -8,
	FFA_NO_DATA            = -9,
	FFA_NOT_READY          = -10,
};

/* clang-format on */

/* Return the name of the function identifier. */
static inline const char *ffa_func_name(uint32_t func)
{
	switch (func) {
	case FFA_ERROR_32:
		return "FFA_ERROR_32";
	case FFA_SUCCESS_32:
		return "FFA_SUCCESS_32";
	case FFA_SUCCESS_64:
		return "FFA_SUCCESS_64";
	case FFA_INTERRUPT_32:
		return "FFA_INTERRUPT_32";
	case FFA_VERSION_32:
		return "FFA_VERSION_32";
	case FFA_FEATURES_32:
		return "FFA_FEATURES_32";
	case FFA_RX_RELEASE_32:
		return "FFA_RX_RELEASE_32";
	case FFA_RXTX_MAP_32:
		return "FFA_RXTX_MAP_32";
	case FFA_RXTX_MAP_64:
		return "FFA_RXTX_MAP_64";
	case FFA_RXTX_UNMAP_32:
		return "FFA_RXTX_UNMAP_32";
	case FFA_PARTITION_INFO_GET_32:
		return "FFA_PARTITION_INFO_GET_32";
	case FFA_ID_GET_32:
		return "FFA_ID_GET_32";
	case FFA_MSG_POLL_32:
		return "FFA_MSG_POLL_32";
	case FFA_MSG_WAIT_32:
		return "FFA_MSG_WAIT_32";
	case FFA_YIELD_32:
		return "FFA_YIELD_32";
	case FFA_RUN_32:
		return "FFA_RUN_32";
	case FFA_MSG_SEND_32:
		return "FFA_MSG_SEND_32";
	case FFA_MSG_SEND_DIRECT_REQ_32:
		return "FFA_MSG_SEND_DIRECT_REQ_32";
	case FFA_MSG_SEND_DIRECT_REQ_64:
		return "FFA_MSG_SEND_DIRECT_REQ_64";
	case FFA_MSG_SEND_DIRECT_RESP_32:
		return "FFA_MSG_SEND_DIRECT_RESP_32";
	case FFA_MSG_SEND_DIRECT_RESP_64:
		return "FFA_MSG_SEND_DIRECT_RESP_64";
	case FFA_MEM_DONATE_32:
		return "FFA_MEM_DONATE_32";
	case FFA_MEM_LEND_32:
		return "FFA_MEM_LEND_32";
	case FFA_MEM_SHARE_32:
		return "FFA_MEM_SHARE_32";
	case FFA_MEM_RETRIEVE_REQ_32:
		return "FFA_MEM_RETRIEVE_REQ_32";
	case FFA_MEM_DONATE_64:
		return "FFA_MEM_DONATE_64";
	case FFA_MEM_LEND_64:
		return "FFA_MEM_LEND_64";
	case FFA_MEM_SHARE_64:
		return "FFA_MEM_SHARE_64";
	case FFA_MEM_RETRIEVE_REQ_64:
		return "FFA_MEM_RETRIEVE_REQ_64";
	case FFA_MEM_RETRIEVE_RESP_32:
		return "FFA_MEM_RETRIEVE_RESP_32";
	case FFA_MEM_RELINQUISH_32:
		return "FFA_MEM_RELINQUISH_32";
	case FFA_MEM_RECLAIM_32:
		return "FFA_MEM_RECLAIM_32";
	case FFA_MEM_FRAG_RX_32:
		return "FFA_MEM_FRAG_RX_32";
	case FFA_MEM_FRAG_TX_32:
		return "FFA_MEM_FRAG_TX_32";
	case FFA_NORMAL_WORLD_RESUME:
		return "FFA_NORMAL_WORLD_RESUME";

	/* FF-A v1.1 */
	case FFA_NOTIFICATION_BITMAP_CREATE_32:
		return "FFA_NOTIFICATION_BITMAP_CREATE_32";
	case FFA_NOTIFICATION_BITMAP_DESTROY_32:
		return "FFA_NOTIFICATION_BITMAP_DESTROY_32";
	case FFA_NOTIFICATION_BIND_32:
		return "FFA_NOTIFICATION_BIND_32";
	case FFA_NOTIFICATION_UNBIND_32:
		return "FFA_NOTIFICATION_UNBIND_32";
	case FFA_NOTIFICATION_SET_32:
		return "FFA_NOTIFICATION_SET_32";
	case FFA_NOTIFICATION_GET_32:
		return "FFA_NOTIFICATION_GET_32";
	case FFA_NOTIFICATION_INFO_GET_64:
		return "FFA_NOTIFICATION_INFO_GET_64";
	case FFA_RX_ACQUIRE_32:
		return "FFA_RX_ACQUIRE_32";
	case FFA_SPM_ID_GET_32:
		return "FFA_SPM_ID_GET_32";
	case FFA_MSG_SEND2_32:
		return "FFA_MSG_SEND2_32";
	case FFA_SECONDARY_EP_REGISTER_64:
		return "FFA_SECONDARY_EP_REGISTER_64";
	case FFA_MEM_PERM_GET_32:
		return "FFA_MEM_PERM_GET_32";
	case FFA_MEM_PERM_SET_32:
		return "FFA_MEM_PERM_SET_32";
	case FFA_MEM_PERM_GET_64:
		return "FFA_MEM_PERM_GET_64";
	case FFA_MEM_PERM_SET_64:
		return "FFA_MEM_PERM_SET_64";

	/* Implementation-defined ABIs. */
	case FFA_CONSOLE_LOG_32:
		return "FFA_CONSOLE_LOG_32";
	case FFA_CONSOLE_LOG_64:
		return "FFA_CONSOLE_LOG_64";
	case FFA_PARTITION_INFO_GET_REGS_64:
		return "FFA_PARTITION_INFO_GET_REGS_64";
	case FFA_EL3_INTR_HANDLE_32:
		return "FFA_EL3_INTR_HANDLE_32";

	default:
		return "UNKNOWN";
	}
}

/* Return the name of the error code. */
static inline const char *ffa_error_name(enum ffa_error error)
{
	switch (error) {
	case FFA_NOT_SUPPORTED:
		return "FFA_NOT_SUPPORTED";
	case FFA_INVALID_PARAMETERS:
		return "FFA_INVALID_PARAMETERS";
	case FFA_NO_MEMORY:
		return "FFA_NO_MEMORY";
	case FFA_BUSY:
		return "FFA_BUSY";
	case FFA_INTERRUPTED:
		return "FFA_INTERRUPTED";
	case FFA_DENIED:
		return "FFA_DENIED";
	case FFA_RETRY:
		return "FFA_RETRY";
	case FFA_ABORTED:
		return "FFA_ABORTED";
	case FFA_NO_DATA:
		return "FFA_NO_DATA";
	case FFA_NOT_READY:
		return "FFA_NOT_READY";
	}
	return "UNKNOWN";
}

/**
 * Defined in Table 3.1 in the FF-A v.1.2 memory management supplement.
 * Input properties:
 * - Bits[31:2] and Bit[0] are reserved (SBZ).
 * Output properties:
 * - Bit[0]: dynamically allocated buffer support.
 * - Bit[1]: NS bit handling.
 * - Bit[2]: support for retrieval by hypervisor.
 * - Bits[31:3] are reserved (MBZ).
 */
#define FFA_FEATURES_MEM_RETRIEVE_REQ_BUFFER_SUPPORT (0U << 0U)
#define FFA_FEATURES_MEM_RETRIEVE_REQ_NS_SUPPORT (1U << 1U)
#define FFA_FEATURES_MEM_RETRIEVE_REQ_HYPERVISOR_SUPPORT (1U << 2U)

#define FFA_FEATURES_MEM_RETRIEVE_REQ_MBZ_HI_BIT (31U)
#define FFA_FEATURES_MEM_RETRIEVE_REQ_MBZ_LO_BIT (2U)
#define FFA_FEATURES_MEM_RETRIEVE_REQ_MBZ_BIT (0U)

enum ffa_feature_id {
	/* Query interrupt ID of Notification Pending Interrupt. */
	FFA_FEATURE_NPI = 1,

	/* Query interrupt ID of Schedule Receiver Interrupt. */
	FFA_FEATURE_SRI = 2,

	/* Query interrupt ID of the Managed Exit Interrupt. */
	FFA_FEATURE_MEI = 3,
};

/** Constants for bitmasks used in FFA_FEATURES. */
#define FFA_FEATURES_FEATURE_BIT (31U)
#define FFA_FEATURES_FEATURE_MBZ_HI_BIT (30U)
#define FFA_FEATURES_FEATURE_MBZ_LO_BIT (8U)

#define FFA_FEATURES_NS_SUPPORT_BIT (1U)

/* FF-A function specific constants. */
#define FFA_MSG_RECV_BLOCK 0x1
#define FFA_MSG_RECV_BLOCK_MASK 0x1

#define FFA_MSG_SEND_NOTIFY 0x1
#define FFA_MSG_SEND_NOTIFY_MASK 0x1

#define FFA_MEM_RECLAIM_CLEAR 0x1

#define FFA_SLEEP_INDEFINITE 0

#define FFA_MEM_PERM_RO UINT32_C(0x7)
#define FFA_MEM_PERM_RW UINT32_C(0x5)
#define FFA_MEM_PERM_RX UINT32_C(0x3)

#define FFA_MSG_WAIT_FLAG_RETAIN_RX UINT32_C(0x1)
/*
 * Defined in Table 13.34 in the FF-A v1.1 EAC0 specification.
 * The Partition count flag is used by FFA_PARTITION_INFO_GET to specify
 * if partition info descriptors should be returned or just the count.
 */
#define FFA_PARTITION_COUNT_FLAG UINT32_C(0x1)
#define FFA_PARTITION_COUNT_FLAG_MASK (UINT32_C(0x1) << 0)

/**
 * For use where the FF-A specification refers explicitly to '4K pages'. Not to
 * be confused with PAGE_SIZE, which is the translation granule Hafnium is
 * configured to use.
 */
#define FFA_PAGE_SIZE ((size_t)4096)

/** The ID of a VM. These are assigned sequentially starting with an offset. */
typedef uint16_t ffa_id_t;

/**
 * The FF-A v1.2 ALP0, section 6.1 defines that partition IDs are split into two
 * parts:
 * - Bit15 -> partition type identifier.
 *   - b'0 -> ID relates to a VM ID.
 *   - b'1 -> ID relates to an SP ID.
 */
#define FFA_ID_MASK ((ffa_id_t)0x8000)
#define FFA_VM_ID_MASK ((ffa_id_t)0x0000)

/**
 * Helper to check if FF-A ID is a VM ID, managed by the hypervisor.
 */
static inline bool ffa_is_vm_id(ffa_id_t id)
{
	return (FFA_ID_MASK & id) == FFA_VM_ID_MASK;
}

/**
 * Partition message header as specified by table 6.2 from FF-A v1.1 EAC0
 * specification.
 */
struct ffa_partition_rxtx_header {
	uint32_t flags; /* MBZ */
	uint32_t reserved;
	/* Offset from the beginning of the buffer to the message payload. */
	uint32_t offset;
	/* Sender(Bits[31:16]) and Receiver(Bits[15:0]) endpoint IDs. */
	uint32_t sender_receiver;
	/* Size of message in buffer. */
	uint32_t size;
};

#define FFA_RXTX_HEADER_SIZE sizeof(struct ffa_partition_rxtx_header)
#define FFA_RXTX_SENDER_SHIFT (0x10U)
#define FFA_RXTX_ALLOCATOR_SHIFT 16

static inline void ffa_rxtx_header_init(
	ffa_id_t sender, ffa_id_t receiver, uint32_t size,
	struct ffa_partition_rxtx_header *header)
{
	header->flags = 0;
	header->reserved = 0;
	header->offset = FFA_RXTX_HEADER_SIZE;
	header->sender_receiver =
		(uint32_t)(receiver | (sender << FFA_RXTX_SENDER_SHIFT));
	header->size = size;
}

static inline ffa_id_t ffa_rxtx_header_sender(
	const struct ffa_partition_rxtx_header *h)
{
	return (ffa_id_t)(h->sender_receiver >> FFA_RXTX_SENDER_SHIFT);
}

static inline ffa_id_t ffa_rxtx_header_receiver(
	const struct ffa_partition_rxtx_header *h)
{
	return (ffa_id_t)(h->sender_receiver);
}

/* The maximum length possible for a single message. */
#define FFA_PARTITION_MSG_PAYLOAD_MAX (HF_MAILBOX_SIZE - FFA_RXTX_HEADER_SIZE)

struct ffa_partition_msg {
	struct ffa_partition_rxtx_header header;
	char payload[FFA_PARTITION_MSG_PAYLOAD_MAX];
};

/* The maximum length possible for a single message. */
#define FFA_MSG_PAYLOAD_MAX HF_MAILBOX_SIZE

enum ffa_data_access {
	FFA_DATA_ACCESS_NOT_SPECIFIED,
	FFA_DATA_ACCESS_RO,
	FFA_DATA_ACCESS_RW,
	FFA_DATA_ACCESS_RESERVED,
};

static inline const char *ffa_data_access_name(enum ffa_data_access data_access)
{
	switch (data_access) {
	case FFA_DATA_ACCESS_NOT_SPECIFIED:
		return "FFA_DATA_ACCESS_NOT_SPECIFIED";
	case FFA_DATA_ACCESS_RO:
		return "FFA_DATA_ACCESS_RO";
	case FFA_DATA_ACCESS_RW:
		return "FFA_DATA_ACCESS_RW";
	case FFA_DATA_ACCESS_RESERVED:
		return "FFA_DATA_ACCESS_RESERVED";
	}
}

enum ffa_instruction_access {
	FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
	FFA_INSTRUCTION_ACCESS_NX,
	FFA_INSTRUCTION_ACCESS_X,
	FFA_INSTRUCTION_ACCESS_RESERVED,
};

static inline const char *ffa_instruction_access_name(
	enum ffa_instruction_access instruction_access)
{
	switch (instruction_access) {
	case FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED:
		return "FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED";
	case FFA_INSTRUCTION_ACCESS_NX:
		return "FFA_INSTRUCTION_ACCESS_NX";
	case FFA_INSTRUCTION_ACCESS_X:
		return "FFA_INSTRUCTION_ACCESS_X";
	case FFA_INSTRUCTION_ACCESS_RESERVED:
		return "FFA_INSTRUCTION_ACCESS_RESERVED";
	}
}

enum ffa_memory_type {
	FFA_MEMORY_NOT_SPECIFIED_MEM,
	FFA_MEMORY_DEVICE_MEM,
	FFA_MEMORY_NORMAL_MEM,
};

static inline const char *ffa_memory_type_name(enum ffa_memory_type type)
{
	switch (type) {
	case FFA_MEMORY_NOT_SPECIFIED_MEM:
		return "FFA_MEMORY_NOT_SPECIFIED_MEM";
	case FFA_MEMORY_DEVICE_MEM:
		return "FFA_MEMORY_DEVICE_MEM";
	case FFA_MEMORY_NORMAL_MEM:
		return "FFA_MEMORY_NORMAL_MEM";
	}
}

enum ffa_memory_cacheability {
	FFA_MEMORY_CACHE_RESERVED = 0x0,
	FFA_MEMORY_CACHE_NON_CACHEABLE = 0x1,
	FFA_MEMORY_CACHE_RESERVED_1 = 0x2,
	FFA_MEMORY_CACHE_WRITE_BACK = 0x3,
	FFA_MEMORY_DEV_NGNRNE = 0x0,
	FFA_MEMORY_DEV_NGNRE = 0x1,
	FFA_MEMORY_DEV_NGRE = 0x2,
	FFA_MEMORY_DEV_GRE = 0x3,
};

static inline const char *ffa_memory_cacheability_name(
	enum ffa_memory_cacheability cacheability)
{
	switch (cacheability) {
	case FFA_MEMORY_CACHE_RESERVED:
		return "FFA_MEMORY_CACHE_RESERVED";
	case FFA_MEMORY_CACHE_NON_CACHEABLE:
		return "FFA_MEMORY_CACHE_NON_CACHEABLE";
	case FFA_MEMORY_CACHE_RESERVED_1:
		return "FFA_MEMORY_CACHE_RESERVED_1";
	case FFA_MEMORY_CACHE_WRITE_BACK:
		return "FFA_MEMORY_CACHE_WRITE_BACK";
	}
}

static inline const char *ffa_device_memory_cacheability_name(
	enum ffa_memory_cacheability cacheability)
{
	switch (cacheability) {
	case FFA_MEMORY_DEV_NGNRNE:
		return "FFA_MEMORY_DEV_NGNRNE";
	case FFA_MEMORY_DEV_NGNRE:
		return "FFA_MEMORY_DEV_NGNRE";
	case FFA_MEMORY_DEV_NGRE:
		return "FFA_MEMORY_DEV_NGRE";
	case FFA_MEMORY_DEV_GRE:
		return "FFA_MEMORY_DEV_GRE";
	}
}

enum ffa_memory_shareability {
	FFA_MEMORY_SHARE_NON_SHAREABLE,
	FFA_MEMORY_SHARE_RESERVED,
	FFA_MEMORY_OUTER_SHAREABLE,
	FFA_MEMORY_INNER_SHAREABLE,
};

static inline const char *ffa_memory_shareability_name(
	enum ffa_memory_shareability shareability)
{
	switch (shareability) {
	case FFA_MEMORY_SHARE_NON_SHAREABLE:
		return "FFA_MEMORY_SHARE_NON_SHAREABLE";
	case FFA_MEMORY_SHARE_RESERVED:
		return "FFA_MEMORY_SHARE_RESERVED";
	case FFA_MEMORY_OUTER_SHAREABLE:
		return "FFA_MEMORY_OUTER_SHAREABLE";
	case FFA_MEMORY_INNER_SHAREABLE:
		return "FFA_MEMORY_INNER_SHAREABLE";
	}
}

/**
 * FF-A v1.1 REL0 Table 10.18 memory region attributes descriptor NS Bit 6.
 * Per section 10.10.4.1, NS bit is reserved for FFA_MEM_DONATE/LEND/SHARE
 * and FFA_MEM_RETRIEVE_REQUEST.
 */
enum ffa_memory_security {
	FFA_MEMORY_SECURITY_UNSPECIFIED = 0,
	FFA_MEMORY_SECURITY_SECURE = 0,
	FFA_MEMORY_SECURITY_NON_SECURE,
};

static inline const char *ffa_memory_security_name(
	enum ffa_memory_security security)
{
	switch (security) {
	case FFA_MEMORY_SECURITY_UNSPECIFIED:
		return "FFA_MEMORY_SECURITY_UNSPECIFIED";
	case FFA_MEMORY_SECURITY_NON_SECURE:
		return "FFA_MEMORY_SECURITY_NON_SECURE";
	}
}

typedef struct {
	uint8_t data_access : 2;
	uint8_t instruction_access : 2;
} ffa_memory_access_permissions_t;

/**
 * This corresponds to table 10.18 of the FF-A v1.1 EAC0 specification, "Memory
 * region attributes descriptor".
 */
typedef struct {
	uint8_t shareability : 2;
	uint8_t cacheability : 2;
	uint8_t type : 2;
	uint8_t security : 2;
	uint8_t : 8;
} ffa_memory_attributes_t;

/* FF-A v1.1 EAC0 states bit [15:7] Must Be Zero. */
#define FFA_MEMORY_ATTRIBUTES_MBZ_MASK 0xFF80U

/**
 * A globally-unique ID assigned by the hypervisor for a region of memory being
 * sent between VMs.
 */
typedef uint64_t ffa_memory_handle_t;

#define FFA_MEMORY_HANDLE_ALLOCATOR_MASK \
	((ffa_memory_handle_t)(UINT64_C(1) << 63))
#define FFA_MEMORY_HANDLE_ALLOCATOR_HYPERVISOR \
	((ffa_memory_handle_t)(UINT64_C(1) << 63))

#define FFA_MEMORY_HANDLE_ALLOCATOR_SPMC (UINT64_C(0) << 63)
#define FFA_MEMORY_HANDLE_INVALID (~UINT64_C(0))

/**
 * A count of VMs. This has the same range as the VM IDs but we give it a
 * different name to make the different semantics clear.
 */
typedef ffa_id_t ffa_vm_count_t;

/** The index of a vCPU within a particular VM. */
typedef uint16_t ffa_vcpu_index_t;

/**
 * A count of vCPUs. This has the same range as the vCPU indices but we give it
 * a different name to make the different semantics clear.
 */
typedef ffa_vcpu_index_t ffa_vcpu_count_t;

/** Parameter and return type of FF-A functions. */
struct ffa_value {
	uint64_t func;
	uint64_t arg1;
	uint64_t arg2;
	uint64_t arg3;
	uint64_t arg4;
	uint64_t arg5;
	uint64_t arg6;
	uint64_t arg7;

	struct {
		uint64_t arg8;
		uint64_t arg9;
		uint64_t arg10;
		uint64_t arg11;
		uint64_t arg12;
		uint64_t arg13;
		uint64_t arg14;
		uint64_t arg15;
		uint64_t arg16;
		uint64_t arg17;
		bool valid;
	} extended_val;
};

static inline uint32_t ffa_func_id(struct ffa_value args)
{
	return args.func;
}

static inline enum ffa_error ffa_error_code(struct ffa_value val)
{
	/* NOLINTNEXTLINE(EnumCastOutOfRange) */
	return (enum ffa_error)val.arg2;
}

static inline ffa_id_t ffa_sender(struct ffa_value args)
{
	return (args.arg1 >> 16) & 0xffff;
}

static inline ffa_id_t ffa_receiver(struct ffa_value args)
{
	return args.arg1 & 0xffff;
}

static inline uint32_t ffa_msg_send_size(struct ffa_value args)
{
	return args.arg3;
}

static inline uint32_t ffa_msg_send2_flags(struct ffa_value args)
{
	return args.arg2;
}

static inline uint32_t ffa_partition_info_get_count(struct ffa_value args)
{
	return args.arg2;
}

static inline uint16_t ffa_partition_info_regs_get_last_idx(
	struct ffa_value args)
{
	return args.arg2 & 0xFFFF;
}

static inline uint16_t ffa_partition_info_regs_get_curr_idx(
	struct ffa_value args)
{
	return (args.arg2 >> 16) & 0xFFFF;
}

static inline uint16_t ffa_partition_info_regs_get_tag(struct ffa_value args)
{
	return (args.arg2 >> 32) & 0xFFFF;
}

static inline uint16_t ffa_partition_info_regs_get_desc_size(
	struct ffa_value args)
{
	return (args.arg2 >> 48);
}

static inline ffa_memory_handle_t ffa_assemble_handle(uint32_t a1, uint32_t a2)
{
	return (uint64_t)a1 | (uint64_t)a2 << 32;
}

static inline ffa_memory_handle_t ffa_mem_success_handle(struct ffa_value args)
{
	return ffa_assemble_handle(args.arg2, args.arg3);
}

static inline ffa_memory_handle_t ffa_frag_handle(struct ffa_value args)
{
	return ffa_assemble_handle(args.arg1, args.arg2);
}

static inline struct ffa_value ffa_mem_success(ffa_memory_handle_t handle)
{
	return (struct ffa_value){.func = FFA_SUCCESS_32,
				  .arg2 = (uint32_t)handle,
				  .arg3 = (uint32_t)(handle >> 32)};
}

static inline ffa_id_t ffa_vm_id(struct ffa_value args)
{
	return (args.arg1 >> 16) & 0xffff;
}

static inline ffa_vcpu_index_t ffa_vcpu_index(struct ffa_value args)
{
	return args.arg1 & 0xffff;
}

static inline uint64_t ffa_vm_vcpu(ffa_id_t vm_id, ffa_vcpu_index_t vcpu_index)
{
	return ((uint32_t)vm_id << 16) | vcpu_index;
}

static inline ffa_id_t ffa_frag_sender(struct ffa_value args)
{
	return (args.arg4 >> 16) & 0xffff;
}

static inline uint32_t ffa_feature_intid(struct ffa_value args)
{
	return (uint32_t)args.arg2;
}

#define FFA_FRAMEWORK_MSG_BIT (UINT64_C(1) << 31)
#define FFA_FRAMEWORK_MSG_FUNC_MASK UINT64_C(0xFF)

/**
 * Identifies the VM availability message. See section 18.3 of v1.2 FF-A
 * specification.
 */
enum ffa_framework_msg_func {
	FFA_FRAMEWORK_MSG_VM_CREATION_REQ = 4,
	FFA_FRAMEWORK_MSG_VM_CREATION_RESP = 5,

	FFA_FRAMEWORK_MSG_VM_DESTRUCTION_REQ = 6,
	FFA_FRAMEWORK_MSG_VM_DESTRUCTION_RESP = 7,
};

#define FFA_VM_AVAILABILITY_MESSAGE_SBZ_LO 16
#define FFA_VM_AVAILABILITY_MESSAGE_SBZ_HI 31

/** Get the `flags` field of a framework message */
static inline uint32_t ffa_framework_msg_flags(struct ffa_value args)
{
	return (uint32_t)args.arg2;
}

/** Is `args` a framework message? */
static inline bool ffa_is_framework_msg(struct ffa_value args)
{
	return (args.func != FFA_MSG_SEND_DIRECT_REQ2_64) &&
	       (args.func != FFA_MSG_SEND_DIRECT_RESP2_64) &&
	       ((ffa_framework_msg_flags(args) & FFA_FRAMEWORK_MSG_BIT) != 0);
}

/**
 * Get the ID of the VM that has been created/destroyed from VM availability
 * message
 */
static inline ffa_id_t ffa_vm_availability_message_vm_id(struct ffa_value args)
{
	return args.arg5 & 0xFFFF;
}

/** Get the function ID from a framework message */
static inline uint32_t ffa_framework_msg_func(struct ffa_value args)
{
	return ffa_framework_msg_flags(args) & FFA_FRAMEWORK_MSG_FUNC_MASK;
}

/**
 * Holds the UUID in a struct that is mappable directly to the SMCC calling
 * convention, which is used for FF-A calls.
 *
 * Refer to table 84 of the FF-A 1.0 EAC specification as well as section 5.3
 * of the SMCC Spec 1.2.
 */
struct ffa_uuid {
	uint32_t uuid[4];
};

static inline void ffa_uuid_init(uint32_t w0, uint32_t w1, uint32_t w2,
				 uint32_t w3, struct ffa_uuid *uuid)
{
	uuid->uuid[0] = w0;
	uuid->uuid[1] = w1;
	uuid->uuid[2] = w2;
	uuid->uuid[3] = w3;
}

static inline bool ffa_uuid_equal(const struct ffa_uuid *uuid1,
				  const struct ffa_uuid *uuid2)
{
	return (uuid1->uuid[0] == uuid2->uuid[0]) &&
	       (uuid1->uuid[1] == uuid2->uuid[1]) &&
	       (uuid1->uuid[2] == uuid2->uuid[2]) &&
	       (uuid1->uuid[3] == uuid2->uuid[3]);
}

static inline bool ffa_uuid_is_null(const struct ffa_uuid *uuid)
{
	struct ffa_uuid null = {0};

	return ffa_uuid_equal(uuid, &null);
}

static inline void ffa_uuid_from_u64x2(uint64_t uuid_lo, uint64_t uuid_hi,
				       struct ffa_uuid *uuid)
{
	ffa_uuid_init((uint32_t)(uuid_lo & 0xFFFFFFFFU),
		      (uint32_t)(uuid_lo >> 32),
		      (uint32_t)(uuid_hi & 0xFFFFFFFFU),
		      (uint32_t)(uuid_hi >> 32), uuid);
}

/**
 * Split `uuid` into two u64s.
 * This function writes to pointer parameters because C does not allow returning
 * arrays from functions.
 */
static inline void ffa_uuid_to_u64x2(uint64_t *lo, uint64_t *hi,
				     const struct ffa_uuid *uuid)
{
	*lo = (uint64_t)uuid->uuid[1] << 32 | uuid->uuid[0];
	*hi = (uint64_t)uuid->uuid[3] << 32 | uuid->uuid[2];
}

/**
 * Flags to determine the partition properties, as required by
 * FFA_PARTITION_INFO_GET.
 *
 * The values of the flags are specified in table 6.2 of DEN0077A FF-A 1.2 ALP0
 * specification, "Partition information descriptor, partition properties".
 */
typedef uint32_t ffa_partition_properties_t;

/**
 * Partition property: partition supports receipt of direct requests via the
 * FFA_MSG_SEND_DIRECT_REQ ABI.
 */
#define FFA_PARTITION_DIRECT_REQ_RECV (UINT32_C(1) << 0)

/**
 * Partition property: partition can send direct requests via the
 * FFA_MSG_SEND_DIRECT_REQ ABI.
 */
#define FFA_PARTITION_DIRECT_REQ_SEND (UINT32_C(1) << 1)

/** Partition property: partition can send and receive indirect messages. */
#define FFA_PARTITION_INDIRECT_MSG (UINT32_C(1) << 2)

/** Partition property: partition can receive notifications. */
#define FFA_PARTITION_NOTIFICATION (UINT32_C(1) << 3)

/**
 * Partition property: partition must be informed about each VM that is created
 * by the Hypervisor.
 */
#define FFA_PARTITION_VM_CREATED (UINT32_C(1) << 6)

/**
 * Partition property: partition must be informed about each VM that is
 * destroyed by the Hypervisor.
 */
#define FFA_PARTITION_VM_DESTROYED (UINT32_C(1) << 7)

/** Partition property: partition runs in the AArch64 execution state. */
#define FFA_PARTITION_AARCH64_EXEC (UINT32_C(1) << 8)

/**
 * Partition property: partition supports receipt of direct requests via the
 * FFA_MSG_SEND_DIRECT_REQ2 ABI.
 */
#define FFA_PARTITION_DIRECT_REQ2_RECV (UINT32_C(1) << 9)

/**
 * Partition property: partition can send direct requests via the
 * FFA_MSG_SEND_DIRECT_REQ2 ABI.
 */
#define FFA_PARTITION_DIRECT_REQ2_SEND (UINT32_C(1) << 10)

/**
 * Holds information returned for each partition by the FFA_PARTITION_INFO_GET
 * interface.
 * This corresponds to table 13.37 "Partition information descriptor"
 * in FF-A 1.1 EAC0 specification.
 */
struct ffa_partition_info {
	ffa_id_t vm_id;
	ffa_vcpu_count_t vcpu_count;
	ffa_partition_properties_t properties;
	struct ffa_uuid uuid;
};

/** Length in bytes of the name in boot information descriptor. */
#define FFA_BOOT_INFO_NAME_LEN 16

/**
 * The FF-A boot info descriptor, as defined in table 5.8 of section 5.4.1, of
 * the FF-A v1.1 EAC0 specification.
 */
struct ffa_boot_info_desc {
	char name[FFA_BOOT_INFO_NAME_LEN];
	uint8_t type;
	uint8_t reserved;
	uint16_t flags;
	uint32_t size;
	uint64_t content;
};

/** FF-A boot information type mask. */
#define FFA_BOOT_INFO_TYPE_SHIFT 7
#define FFA_BOOT_INFO_TYPE_MASK (0x1U << FFA_BOOT_INFO_TYPE_SHIFT)
#define FFA_BOOT_INFO_TYPE_STD 0U
#define FFA_BOOT_INFO_TYPE_IMPDEF 1U

/** Standard boot info type IDs. */
#define FFA_BOOT_INFO_TYPE_ID_MASK 0x7FU
#define FFA_BOOT_INFO_TYPE_ID_FDT 0U
#define FFA_BOOT_INFO_TYPE_ID_HOB 1U

/** FF-A Boot Info descriptors flags. */
#define FFA_BOOT_INFO_FLAG_MBZ_MASK 0xFFF0U

/** Bits [1:0] encode the format of the name field in ffa_boot_info_desc. */
#define FFA_BOOT_INFO_FLAG_NAME_FORMAT_SHIFT 0U
#define FFA_BOOT_INFO_FLAG_NAME_FORMAT_MASK \
	(0x3U << FFA_BOOT_INFO_FLAG_NAME_FORMAT_SHIFT)
#define FFA_BOOT_INFO_FLAG_NAME_FORMAT_STRING 0x0U
#define FFA_BOOT_INFO_FLAG_NAME_FORMAT_UUID 0x1U

/** Bits [3:2] encode the format of the content field in ffa_boot_info_desc. */
#define FFA_BOOT_INFO_FLAG_CONTENT_FORMAT_SHIFT 2
#define FFA_BOOT_INFO_FLAG_CONTENT_FORMAT_MASK \
	(0x3U << FFA_BOOT_INFO_FLAG_CONTENT_FORMAT_SHIFT)
#define FFA_BOOT_INFO_FLAG_CONTENT_FORMAT_VALUE 0x1U
#define FFA_BOOT_INFO_FLAG_CONTENT_FORMAT_ADDR 0x0U

static inline uint16_t ffa_boot_info_content_format(
	struct ffa_boot_info_desc *desc)
{
	return (desc->flags & FFA_BOOT_INFO_FLAG_CONTENT_FORMAT_MASK) >>
	       FFA_BOOT_INFO_FLAG_CONTENT_FORMAT_SHIFT;
}

static inline uint16_t ffa_boot_info_name_format(
	struct ffa_boot_info_desc *desc)
{
	return (desc->flags & FFA_BOOT_INFO_FLAG_NAME_FORMAT_MASK) >>
	       FFA_BOOT_INFO_FLAG_NAME_FORMAT_SHIFT;
}

static inline uint8_t ffa_boot_info_type_id(struct ffa_boot_info_desc *desc)
{
	return desc->type & FFA_BOOT_INFO_TYPE_ID_MASK;
}

static inline uint8_t ffa_boot_info_type(struct ffa_boot_info_desc *desc)
{
	return (desc->type & FFA_BOOT_INFO_TYPE_MASK) >>
	       FFA_BOOT_INFO_TYPE_SHIFT;
}

/** Length in bytes of the signature in the boot descriptor. */
#define FFA_BOOT_INFO_HEADER_SIGNATURE_LEN 4

/**
 * The FF-A boot information header, as defined in table 5.9 of section 5.4.2,
 * of the FF-A v1.1 EAC0 specification.
 */
struct ffa_boot_info_header {
	uint32_t signature;
	uint32_t version;
	uint32_t info_blob_size;
	uint32_t desc_size;
	uint32_t desc_count;
	uint32_t desc_offset;
	uint64_t reserved;
	struct ffa_boot_info_desc boot_info[];
};

/**
 * FF-A v1.1 specification restricts the number of notifications to a maximum
 * of 64. Following all possible bitmaps.
 */
#define FFA_NOTIFICATION_MASK(ID) (UINT64_C(1) << (ID))

typedef uint64_t ffa_notifications_bitmap_t;

#define MAX_FFA_NOTIFICATIONS 64U

/**
 * Flag for notification bind and set, to specify call is about per-vCPU
 * notifications.
 */
#define FFA_NOTIFICATION_FLAG_PER_VCPU (UINT32_C(1) << 0)

#define FFA_NOTIFICATION_SPM_BUFFER_FULL_MASK FFA_NOTIFICATION_MASK(0)
#define FFA_NOTIFICATION_HYP_BUFFER_FULL_MASK FFA_NOTIFICATION_MASK(32)

/**
 * Helper functions to check for buffer full notification.
 */
static inline bool is_ffa_hyp_buffer_full_notification(
	ffa_notifications_bitmap_t framework)
{
	return (framework & FFA_NOTIFICATION_HYP_BUFFER_FULL_MASK) != 0;
}

static inline bool is_ffa_spm_buffer_full_notification(
	ffa_notifications_bitmap_t framework)
{
	return (framework & FFA_NOTIFICATION_SPM_BUFFER_FULL_MASK) != 0;
}

/**
 * Helper function to assemble a 64-bit sized bitmap, from the 32-bit sized lo
 * and hi.
 * Helpful as FF-A specification defines that the notifications interfaces
 * arguments are 32-bit registers.
 */
static inline ffa_notifications_bitmap_t ffa_notifications_bitmap(uint32_t lo,
								  uint32_t hi)
{
	return (ffa_notifications_bitmap_t)hi << 32U | lo;
}

static inline ffa_notifications_bitmap_t ffa_notification_get_from_sp(
	struct ffa_value val)
{
	return ffa_notifications_bitmap((uint32_t)val.arg2, (uint32_t)val.arg3);
}

static inline ffa_notifications_bitmap_t ffa_notification_get_from_vm(
	struct ffa_value val)
{
	return ffa_notifications_bitmap((uint32_t)val.arg4, (uint32_t)val.arg5);
}

static inline ffa_notifications_bitmap_t ffa_notification_get_from_framework(
	struct ffa_value val)
{
	return ffa_notifications_bitmap((uint32_t)val.arg6, (uint32_t)val.arg7);
}

/**
 * Flags used in calls to FFA_NOTIFICATION_GET interface.
 */
#define FFA_NOTIFICATION_FLAG_BITMAP_SP (UINT32_C(1) << 0)
#define FFA_NOTIFICATION_FLAG_BITMAP_VM (UINT32_C(1) << 1)
#define FFA_NOTIFICATION_FLAG_BITMAP_SPM (UINT32_C(1) << 2)
#define FFA_NOTIFICATION_FLAG_BITMAP_HYP (UINT32_C(1) << 3)

/* Flag to configure notification as being per vCPU. */
#define FFA_NOTIFICATIONS_FLAG_PER_VCPU (UINT32_C(1) << 0)

/** Flag for FFA_NOTIFICATION_SET to delay Schedule Receiver Interrupt */
#define FFA_NOTIFICATIONS_FLAG_DELAY_SRI (UINT32_C(1) << 1)

#define FFA_NOTIFICATIONS_FLAGS_VCPU_ID(id) \
	((((uint32_t)(id)) & UINT32_C(0xffff)) << 16)

static inline ffa_vcpu_index_t ffa_notifications_get_vcpu(struct ffa_value args)
{
	return (ffa_vcpu_index_t)(args.arg1 >> 16 & 0xffffU);
}

/**
 * The max number of IDs for return of FFA_NOTIFICATION_INFO_GET.
 */
#define FFA_NOTIFICATIONS_INFO_GET_MAX_IDS 20U

/**
 * Number of registers to use in successfull return of interface
 * FFA_NOTIFICATION_INFO_GET.
 */
#define FFA_NOTIFICATIONS_INFO_GET_REGS_RET 5U

#define FFA_NOTIFICATIONS_INFO_GET_FLAG_MORE_PENDING 0x1U

/**
 * Helper macros for return parameter encoding as described in section 17.7.1
 * of the FF-A v1.1 Beta0 specification.
 */
#define FFA_NOTIFICATIONS_LISTS_COUNT_SHIFT 0x7U
#define FFA_NOTIFICATIONS_LISTS_COUNT_MASK 0x1fU
#define FFA_NOTIFICATIONS_LIST_SHIFT(l) (2 * ((l) - 1) + 12)
#define FFA_NOTIFICATIONS_LIST_SIZE_MASK 0x3U
#define FFA_NOTIFICATIONS_LIST_MAX_SIZE 0x4U

static inline uint32_t ffa_notification_info_get_lists_count(
	struct ffa_value args)
{
	return (uint32_t)(args.arg2 >> FFA_NOTIFICATIONS_LISTS_COUNT_SHIFT) &
	       FFA_NOTIFICATIONS_LISTS_COUNT_MASK;
}

static inline uint32_t ffa_notification_info_get_list_size(
	struct ffa_value args, unsigned int list_idx)
{
	return ((uint32_t)args.arg2 >> FFA_NOTIFICATIONS_LIST_SHIFT(list_idx)) &
	       FFA_NOTIFICATIONS_LIST_SIZE_MASK;
}

static inline bool ffa_notification_info_get_more_pending(struct ffa_value args)
{
	return (args.arg2 & FFA_NOTIFICATIONS_INFO_GET_FLAG_MORE_PENDING) != 0U;
}

void ffa_notification_info_get_and_check(
	const uint32_t expected_lists_count,
	const uint32_t *const expected_lists_sizes,
	const uint16_t *const expected_ids);

/**
 * A set of contiguous pages which is part of a memory region. This corresponds
 * to table 10.14 of the FF-A v1.1 EAC0 specification, "Constituent memory
 * region descriptor".
 */
struct ffa_memory_region_constituent {
	/**
	 * The base IPA of the constituent memory region, aligned to 4 kiB page
	 * size granularity.
	 */
	uint64_t address;
	/** The number of 4 kiB pages in the constituent memory region. */
	uint32_t page_count;
	/** Reserved field, must be 0. */
	uint32_t reserved;
};

/**
 * A set of pages comprising a memory region. This corresponds to table 10.13 of
 * the FF-A v1.1 EAC0 specification, "Composite memory region descriptor".
 */
struct ffa_composite_memory_region {
	/**
	 * The total number of 4 kiB pages included in this memory region. This
	 * must be equal to the sum of page counts specified in each
	 * `ffa_memory_region_constituent`.
	 */
	uint32_t page_count;
	/**
	 * The number of constituents (`ffa_memory_region_constituent`)
	 * included in this memory region range.
	 */
	uint32_t constituent_count;
	/** Reserved field, must be 0. */
	uint64_t reserved_0;
	/** An array of `constituent_count` memory region constituents. */
	struct ffa_memory_region_constituent constituents[];
};

/** Flags to indicate properties of receivers during memory region retrieval. */
typedef uint8_t ffa_memory_receiver_flags_t;

/**
 * This corresponds to table 10.15 of the FF-A v1.1 EAC0 specification, "Memory
 * access permissions descriptor".
 */
struct ffa_memory_region_attributes {
	/** The ID of the VM to which the memory is being given or shared. */
	ffa_id_t receiver;
	/**
	 * The permissions with which the memory region should be mapped in the
	 * receiver's page table.
	 */
	ffa_memory_access_permissions_t permissions;
	/**
	 * Flags used during FFA_MEM_RETRIEVE_REQ and FFA_MEM_RETRIEVE_RESP
	 * for memory regions with multiple borrowers.
	 */
	ffa_memory_receiver_flags_t flags;
};

/** Flags to control the behaviour of a memory sharing transaction. */
typedef uint32_t ffa_memory_region_flags_t;

/**
 * Clear memory region contents after unmapping it from the sender and before
 * mapping it for any receiver.
 */
#define FFA_MEMORY_REGION_FLAG_CLEAR 0x1

/**
 * Whether the hypervisor may time slice the memory sharing or retrieval
 * operation.
 */
#define FFA_MEMORY_REGION_FLAG_TIME_SLICE 0x2

/**
 * Whether the hypervisor should clear the memory region after the receiver
 * relinquishes it or is aborted.
 */
#define FFA_MEMORY_REGION_FLAG_CLEAR_RELINQUISH 0x4

/**
 * On retrieve request, bypass the multi-borrower check.
 */
#define FFA_MEMORY_REGION_FLAG_BYPASS_BORROWERS_CHECK (0x1U << 10)

#define FFA_MEMORY_REGION_TRANSACTION_TYPE_MASK ((0x3U) << 3)
#define FFA_MEMORY_REGION_TRANSACTION_TYPE_UNSPECIFIED ((0x0U) << 3)
#define FFA_MEMORY_REGION_TRANSACTION_TYPE_SHARE ((0x1U) << 3)
#define FFA_MEMORY_REGION_TRANSACTION_TYPE_LEND ((0x2U) << 3)
#define FFA_MEMORY_REGION_TRANSACTION_TYPE_DONATE ((0x3U) << 3)

#define FFA_MEMORY_REGION_ADDRESS_RANGE_HINT_VALID ((0x1U) << 9)
#define FFA_MEMORY_REGION_ADDRESS_RANGE_HINT_MASK ((0xFU) << 5)

/**
 * Struct to store the impdef value seen in Table 11.16 of the
 * FF-A v1.2 ALP0 specification "Endpoint memory access descriptor".
 */
struct ffa_memory_access_impdef {
	uint64_t val[2];
};

static inline struct ffa_memory_access_impdef ffa_memory_access_impdef_init(
	uint64_t impdef_hi, uint64_t impdef_lo)
{
	return (struct ffa_memory_access_impdef){{impdef_hi, impdef_lo}};
}

/**
 * This corresponds to table 10.16 of the FF-A v1.1 EAC0 specification,
 * "Endpoint memory access descriptor".
 */
struct ffa_memory_access {
	struct ffa_memory_region_attributes receiver_permissions;
	/**
	 * Offset in bytes from the start of the outer `ffa_memory_region` to
	 * an `ffa_composite_memory_region` struct.
	 */
	uint32_t composite_memory_region_offset;
	struct ffa_memory_access_impdef impdef;
	uint64_t reserved_0;
};

/** The maximum number of recipients a memory region may be sent to. */
#define MAX_MEM_SHARE_RECIPIENTS UINT32_C(2)

/**
 * Information about a set of pages which are being shared. This corresponds to
 * table 10.20 of the FF-A v1.1 EAC0 specification, "Lend, donate or share
 * memory transaction descriptor". Note that it is also used for retrieve
 * requests and responses.
 */
struct ffa_memory_region {
	/**
	 * The ID of the VM which originally sent the memory region, i.e. the
	 * owner.
	 */
	ffa_id_t sender;
	ffa_memory_attributes_t attributes;
	/** Flags to control behaviour of the transaction. */
	ffa_memory_region_flags_t flags;
	ffa_memory_handle_t handle;
	/**
	 * An implementation defined value associated with the receiver and the
	 * memory region.
	 */
	uint64_t tag;
	/* Size of the memory access descriptor. */
	uint32_t memory_access_desc_size;
	/**
	 * The number of `ffa_memory_access` entries included in this
	 * transaction.
	 */
	uint32_t receiver_count;
	/**
	 * Offset of the 'receivers' field, which relates to the memory access
	 * descriptors.
	 */
	uint32_t receivers_offset;
	/** Reserved field (12 bytes) must be 0. */
	uint32_t reserved[3];
};

/**
 * Descriptor used for FFA_MEM_RELINQUISH requests. This corresponds to table
 * 16.25 of the FF-A v1.1 EAC0 specification, "Descriptor to relinquish a memory
 * region".
 */
struct ffa_mem_relinquish {
	ffa_memory_handle_t handle;
	ffa_memory_region_flags_t flags;
	uint32_t endpoint_count;
	ffa_id_t endpoints[];
};

/**
 * Returns the first FF-A version that matches the memory access descriptor
 * size.
 */
enum ffa_version ffa_version_from_memory_access_desc_size(
	uint32_t memory_access_desc_size);

/**
 * To maintain forwards compatability we can't make assumptions about the size
 * of the endpoint memory access descriptor so provide a helper function
 * to get a receiver from the receiver array using the memory access descriptor
 * size field from the memory region descriptor struct.
 * Returns NULL if we cannot return the receiver.
 */
static inline struct ffa_memory_access *ffa_memory_region_get_receiver(
	struct ffa_memory_region *memory_region, uint32_t receiver_index)
{
	uint32_t memory_access_desc_size =
		memory_region->memory_access_desc_size;

	if (receiver_index >= memory_region->receiver_count) {
		return NULL;
	}

	/*
	 * Memory access descriptor size cannot be greater than the size of
	 * the memory access descriptor defined by the current FF-A version.
	 */
	if (memory_access_desc_size > sizeof(struct ffa_memory_access)) {
		return NULL;
	}

	/* Check we cannot use receivers offset to cause overflow. */
	if (memory_region->receivers_offset !=
	    sizeof(struct ffa_memory_region)) {
		return NULL;
	}

	return (struct ffa_memory_access
			*)((uint8_t *)memory_region +
			   (size_t)memory_region->receivers_offset +
			   (size_t)(receiver_index * memory_access_desc_size));
}

/**
 * Gets the receiver's access permissions from 'struct ffa_memory_region' and
 * returns its index in the receiver's array. If receiver's ID doesn't exist
 * in the array, return the region's 'receivers_count'.
 */
static inline uint32_t ffa_memory_region_get_receiver_index(
	struct ffa_memory_region *memory_region, ffa_id_t receiver_id)
{
	uint32_t i;

	for (i = 0U; i < memory_region->receiver_count; i++) {
		struct ffa_memory_access *receiver =
			ffa_memory_region_get_receiver(memory_region, i);
		if (receiver->receiver_permissions.receiver == receiver_id) {
			break;
		}
	}

	return i;
}

/**
 * Gets the `ffa_composite_memory_region` for the given receiver from an
 * `ffa_memory_region`, or NULL if it is not valid.
 */
static inline struct ffa_composite_memory_region *
ffa_memory_region_get_composite(struct ffa_memory_region *memory_region,
				uint32_t receiver_index)
{
	struct ffa_memory_access *receiver =
		ffa_memory_region_get_receiver(memory_region, receiver_index);
	uint32_t offset;

	if (receiver == NULL) {
		return NULL;
	}

	offset = receiver->composite_memory_region_offset;
	if (offset == 0) {
		return NULL;
	}

	return (struct ffa_composite_memory_region *)((uint8_t *)memory_region +
						      offset);
}

static inline uint32_t ffa_mem_relinquish_init(
	struct ffa_mem_relinquish *relinquish_request,
	ffa_memory_handle_t handle, ffa_memory_region_flags_t flags,
	ffa_id_t sender)
{
	relinquish_request->handle = handle;
	relinquish_request->flags = flags;
	relinquish_request->endpoint_count = 1;
	relinquish_request->endpoints[0] = sender;
	return sizeof(struct ffa_mem_relinquish) + sizeof(ffa_id_t);
}

void ffa_copy_memory_region_constituents(
	struct ffa_memory_region_constituent *dest,
	const struct ffa_memory_region_constituent *src);

struct ffa_features_rxtx_map_params {
	/*
	 * Bit[0:1]:
	 * Minimum buffer size and alignment boundary:
	 * 0b00: 4K
	 * 0b01: 64K
	 * 0b10: 16K
	 * 0b11: Reserved
	 */
	uint8_t min_buf_size : 2;
	/*
	 * Bit[2:15]:
	 * Reserved (MBZ)
	 */
	uint16_t mbz : 14;
	/*
	 * Bit[16:32]:
	 * Maximum buffer size in number of pages
	 * Only present on version 1.2 or later
	 */
	uint16_t max_buf_size : 16;
};

enum ffa_features_rxtx_map_buf_size {
	FFA_RXTX_MAP_MIN_BUF_4K = 0,
	FFA_RXTX_MAP_MAX_BUF_PAGE_COUNT = 1,
};

static inline struct ffa_features_rxtx_map_params ffa_features_rxtx_map_params(
	struct ffa_value args)
{
	struct ffa_features_rxtx_map_params params;
	uint32_t arg2 = args.arg2;

	params = *(struct ffa_features_rxtx_map_params *)(&arg2);

	return params;
}

/**
 * Endpoint RX/TX descriptor, as defined by Table 13.27 in FF-A v1.1 EAC0.
 * It's used by the Hypervisor to describe the RX/TX buffers mapped by a VM
 * to the SPMC, in order to allow indirect messaging.
 */
struct ffa_endpoint_rx_tx_descriptor {
	ffa_id_t endpoint_id;
	uint16_t reserved;

	/*
	 * 8-byte aligned offset from the base address of this descriptor to the
	 * `ffa_composite_memory_region` describing the RX buffer.
	 */
	uint32_t rx_offset;

	/*
	 * 8-byte aligned offset from the base address of this descriptor to the
	 * `ffa_composite_memory_region` describing the TX buffer.
	 */
	uint32_t tx_offset;

	/* Pad to align on 16-byte boundary. */
	uint32_t pad;
};

static inline struct ffa_composite_memory_region *
ffa_endpoint_get_rx_memory_region(struct ffa_endpoint_rx_tx_descriptor *desc)
{
	return (struct ffa_composite_memory_region *)((char *)desc +
						      desc->rx_offset);
}

static inline struct ffa_composite_memory_region *
ffa_endpoint_get_tx_memory_region(struct ffa_endpoint_rx_tx_descriptor *desc)
{
	return (struct ffa_composite_memory_region *)((char *)desc +
						      desc->tx_offset);
}

void ffa_memory_region_init_header(struct ffa_memory_region *memory_region,
				   ffa_id_t sender,
				   ffa_memory_attributes_t attributes,
				   ffa_memory_region_flags_t flags,
				   ffa_memory_handle_t handle, uint32_t tag,
				   uint32_t receiver_count,
				   uint32_t receiver_desc_size);
void ffa_memory_access_init(struct ffa_memory_access *receiver,
			    ffa_id_t receiver_id,
			    enum ffa_data_access data_access,
			    enum ffa_instruction_access instruction_access,
			    ffa_memory_receiver_flags_t flags,
			    struct ffa_memory_access_impdef *impdef_val);
uint32_t ffa_memory_region_init_single_receiver(
	struct ffa_memory_region *memory_region, size_t memory_region_max_size,
	ffa_id_t sender, ffa_id_t receiver,
	const struct ffa_memory_region_constituent constituents[],
	uint32_t constituent_count, uint32_t tag,
	ffa_memory_region_flags_t flags, enum ffa_data_access data_access,
	enum ffa_instruction_access instruction_access,
	enum ffa_memory_type type, enum ffa_memory_cacheability cacheability,
	enum ffa_memory_shareability shareability,
	struct ffa_memory_access_impdef *impdef_val, uint32_t *fragment_length,
	uint32_t *total_length);
uint32_t ffa_memory_region_init(
	struct ffa_memory_region *memory_region, size_t memory_region_max_size,
	ffa_id_t sender, struct ffa_memory_access receivers[],
	uint32_t receiver_count, uint32_t receiver_desc_size,
	const struct ffa_memory_region_constituent constituents[],
	uint32_t constituent_count, uint32_t tag,
	ffa_memory_region_flags_t flags, enum ffa_memory_type type,
	enum ffa_memory_cacheability cacheability,
	enum ffa_memory_shareability shareability, uint32_t *fragment_length,
	uint32_t *total_length);
uint32_t ffa_memory_retrieve_request_init(
	struct ffa_memory_region *memory_region, ffa_memory_handle_t handle,
	ffa_id_t sender, struct ffa_memory_access receivers[],
	uint32_t receiver_count, uint32_t receiver_desc_size, uint32_t tag,
	ffa_memory_region_flags_t flags, enum ffa_memory_type type,
	enum ffa_memory_cacheability cacheability,
	enum ffa_memory_shareability shareability);
uint32_t ffa_memory_retrieve_request_init_single_receiver(
	struct ffa_memory_region *memory_region, ffa_memory_handle_t handle,
	ffa_id_t sender, ffa_id_t receiver, uint32_t tag,
	ffa_memory_region_flags_t flags, enum ffa_data_access data_access,
	enum ffa_instruction_access instruction_access,
	enum ffa_memory_type type, enum ffa_memory_cacheability cacheability,
	enum ffa_memory_shareability shareability,
	struct ffa_memory_access_impdef *impdef_val);
uint32_t ffa_memory_lender_retrieve_request_init(
	struct ffa_memory_region *memory_region, ffa_memory_handle_t handle,
	ffa_id_t sender);
uint32_t ffa_memory_fragment_init(
	struct ffa_memory_region_constituent *fragment,
	size_t fragment_max_size,
	const struct ffa_memory_region_constituent constituents[],
	uint32_t constituent_count, uint32_t *fragment_length);
void ffa_endpoint_rx_tx_descriptor_init(
	struct ffa_endpoint_rx_tx_descriptor *desc, ffa_id_t endpoint_id,
	uint64_t rx_address, uint64_t tx_address);
