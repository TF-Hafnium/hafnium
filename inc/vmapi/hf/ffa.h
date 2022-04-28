/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "hf/types.h"

#define FFA_VERSION_MAJOR 0x1
#define FFA_VERSION_MAJOR_OFFSET 16
#define FFA_VERSION_MAJOR_MASK 0x7FFF
#define FFA_VERSION_MINOR 0x1
#define FFA_VERSION_MINOR_OFFSET 0
#define FFA_VERSION_MINOR_MASK 0xFFFF

#define MAKE_FFA_VERSION(major, minor)                                    \
	((((major)&FFA_VERSION_MAJOR_MASK) << FFA_VERSION_MAJOR_OFFSET) | \
	 (((minor)&FFA_VERSION_MINOR_MASK) << FFA_VERSION_MINOR_OFFSET))
#define FFA_VERSION_COMPILED \
	MAKE_FFA_VERSION(FFA_VERSION_MAJOR, FFA_VERSION_MINOR)

/* clang-format off */

#define FFA_LOW_32_ID  0x84000060
#define FFA_HIGH_32_ID 0x8400007F
#define FFA_LOW_64_ID  0xC4000060
#define FFA_HIGH_64_ID 0xC400007F

/* FF-A function identifiers. */
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
#define FFA_MEM_LEND_32                     0x84000072
#define FFA_MEM_SHARE_32                    0x84000073
#define FFA_MEM_RETRIEVE_REQ_32             0x84000074
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

/* Implementation-defined ABIs. */
#define FFA_CONSOLE_LOG_32                  0x8400008A
#define FFA_CONSOLE_LOG_64                  0xC400008A

/* FF-A error codes. */
#define FFA_NOT_SUPPORTED      INT32_C(-1)
#define FFA_INVALID_PARAMETERS INT32_C(-2)
#define FFA_NO_MEMORY          INT32_C(-3)
#define FFA_BUSY               INT32_C(-4)
#define FFA_INTERRUPTED        INT32_C(-5)
#define FFA_DENIED             INT32_C(-6)
#define FFA_RETRY              INT32_C(-7)
#define FFA_ABORTED            INT32_C(-8)
#define FFA_NO_DATA            INT32_C(-9)

/* clang-format on */

/**
 * FF-A Feature ID, to be used with interface FFA_FEATURES.
 * As defined in the FF-A v1.1 Beta specification, table 13.10, in section
 * 13.2.
 */

#define FFA_FEATURES_FUNC_ID_MASK (UINT32_C(1) << 31)
#define FFA_FEATURES_FEATURE_ID_MASK UINT32_C(0x7F)

/* Query interrupt ID of Notification Pending Interrupt. */
#define FFA_FEATURE_NPI 0x1U

/* Query interrupt ID of Schedule Receiver Interrupt. */
#define FFA_FEATURE_SRI 0x2U

/* Query interrupt ID of the Managed Exit Interrupt. */
#define FFA_FEATURE_MEI 0x3U

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

/*
 * Defined in Table 13.31 in the FF-A v1.1 BETA0 specification.
 * The Partition count flag is used by FFA_PARTITION_INFO_GET to specify
 * if partition info descriptors should be returned or just the count.
 */
#define FFA_PARTITION_COUNT_FLAG 0x1
#define FFA_PARTITION_COUNT_FLAG_MASK 0x1

/**
 * For use where the FF-A specification refers explicitly to '4K pages'. Not to
 * be confused with PAGE_SIZE, which is the translation granule Hafnium is
 * configured to use.
 */
#define FFA_PAGE_SIZE 4096

/** The ID of a VM. These are assigned sequentially starting with an offset. */
typedef uint16_t ffa_vm_id_t;

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

static inline void ffa_rxtx_header_init(
	ffa_vm_id_t sender, ffa_vm_id_t receiver, uint32_t size,
	struct ffa_partition_rxtx_header *header)
{
	header->flags = 0;
	header->reserved = 0;
	header->offset = FFA_RXTX_HEADER_SIZE;
	header->sender_receiver =
		(uint32_t)(receiver | (sender << FFA_RXTX_SENDER_SHIFT));
	header->size = size;
}

static inline ffa_vm_id_t ffa_rxtx_header_sender(
	const struct ffa_partition_rxtx_header *h)
{
	return (ffa_vm_id_t)(h->sender_receiver >> FFA_RXTX_SENDER_SHIFT);
}

static inline ffa_vm_id_t ffa_rxtx_header_receiver(
	const struct ffa_partition_rxtx_header *h)
{
	return (ffa_vm_id_t)(h->sender_receiver);
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

enum ffa_instruction_access {
	FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
	FFA_INSTRUCTION_ACCESS_NX,
	FFA_INSTRUCTION_ACCESS_X,
	FFA_INSTRUCTION_ACCESS_RESERVED,
};

enum ffa_memory_type {
	FFA_MEMORY_NOT_SPECIFIED_MEM,
	FFA_MEMORY_DEVICE_MEM,
	FFA_MEMORY_NORMAL_MEM,
};

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

enum ffa_memory_shareability {
	FFA_MEMORY_SHARE_NON_SHAREABLE,
	FFA_MEMORY_SHARE_RESERVED,
	FFA_MEMORY_OUTER_SHAREABLE,
	FFA_MEMORY_INNER_SHAREABLE,
};

typedef uint8_t ffa_memory_access_permissions_t;

/**
 * This corresponds to table 44 of the FF-A 1.0 EAC specification, "Memory
 * region attributes descriptor".
 */
typedef uint8_t ffa_memory_attributes_t;

#define FFA_DATA_ACCESS_OFFSET (0x0U)
#define FFA_DATA_ACCESS_MASK ((0x3U) << FFA_DATA_ACCESS_OFFSET)

#define FFA_INSTRUCTION_ACCESS_OFFSET (0x2U)
#define FFA_INSTRUCTION_ACCESS_MASK ((0x3U) << FFA_INSTRUCTION_ACCESS_OFFSET)

#define FFA_MEMORY_TYPE_OFFSET (0x4U)
#define FFA_MEMORY_TYPE_MASK ((0x3U) << FFA_MEMORY_TYPE_OFFSET)

#define FFA_MEMORY_CACHEABILITY_OFFSET (0x2U)
#define FFA_MEMORY_CACHEABILITY_MASK ((0x3U) << FFA_MEMORY_CACHEABILITY_OFFSET)

#define FFA_MEMORY_SHAREABILITY_OFFSET (0x0U)
#define FFA_MEMORY_SHAREABILITY_MASK ((0x3U) << FFA_MEMORY_SHAREABILITY_OFFSET)

#define ATTR_FUNCTION_SET(name, container_type, offset, mask)                \
	static inline void ffa_set_##name##_attr(container_type *attr,       \
						 const enum ffa_##name perm) \
	{                                                                    \
		*attr = (*attr & ~(mask)) | ((perm << offset) & mask);       \
	}

#define ATTR_FUNCTION_GET(name, container_type, offset, mask)      \
	static inline enum ffa_##name ffa_get_##name##_attr(       \
		container_type attr)                               \
	{                                                          \
		return (enum ffa_##name)((attr & mask) >> offset); \
	}

ATTR_FUNCTION_SET(data_access, ffa_memory_access_permissions_t,
		  FFA_DATA_ACCESS_OFFSET, FFA_DATA_ACCESS_MASK)
ATTR_FUNCTION_GET(data_access, ffa_memory_access_permissions_t,
		  FFA_DATA_ACCESS_OFFSET, FFA_DATA_ACCESS_MASK)

ATTR_FUNCTION_SET(instruction_access, ffa_memory_access_permissions_t,
		  FFA_INSTRUCTION_ACCESS_OFFSET, FFA_INSTRUCTION_ACCESS_MASK)
ATTR_FUNCTION_GET(instruction_access, ffa_memory_access_permissions_t,
		  FFA_INSTRUCTION_ACCESS_OFFSET, FFA_INSTRUCTION_ACCESS_MASK)

ATTR_FUNCTION_SET(memory_type, ffa_memory_attributes_t, FFA_MEMORY_TYPE_OFFSET,
		  FFA_MEMORY_TYPE_MASK)
ATTR_FUNCTION_GET(memory_type, ffa_memory_attributes_t, FFA_MEMORY_TYPE_OFFSET,
		  FFA_MEMORY_TYPE_MASK)

ATTR_FUNCTION_SET(memory_cacheability, ffa_memory_attributes_t,
		  FFA_MEMORY_CACHEABILITY_OFFSET, FFA_MEMORY_CACHEABILITY_MASK)
ATTR_FUNCTION_GET(memory_cacheability, ffa_memory_attributes_t,
		  FFA_MEMORY_CACHEABILITY_OFFSET, FFA_MEMORY_CACHEABILITY_MASK)

ATTR_FUNCTION_SET(memory_shareability, ffa_memory_attributes_t,
		  FFA_MEMORY_SHAREABILITY_OFFSET, FFA_MEMORY_SHAREABILITY_MASK)
ATTR_FUNCTION_GET(memory_shareability, ffa_memory_attributes_t,
		  FFA_MEMORY_SHAREABILITY_OFFSET, FFA_MEMORY_SHAREABILITY_MASK)

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
typedef ffa_vm_id_t ffa_vm_count_t;

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
};

static inline uint32_t ffa_func_id(struct ffa_value args)
{
	return args.func;
}

static inline int32_t ffa_error_code(struct ffa_value val)
{
	return (int32_t)val.arg2;
}

static inline ffa_vm_id_t ffa_sender(struct ffa_value args)
{
	return (args.arg1 >> 16) & 0xffff;
}

static inline ffa_vm_id_t ffa_receiver(struct ffa_value args)
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

static inline ffa_vm_id_t ffa_vm_id(struct ffa_value args)
{
	return (args.arg1 >> 16) & 0xffff;
}

static inline ffa_vcpu_index_t ffa_vcpu_index(struct ffa_value args)
{
	return args.arg1 & 0xffff;
}

static inline uint64_t ffa_vm_vcpu(ffa_vm_id_t vm_id,
				   ffa_vcpu_index_t vcpu_index)
{
	return ((uint32_t)vm_id << 16) | vcpu_index;
}

static inline ffa_vm_id_t ffa_frag_sender(struct ffa_value args)
{
	return (args.arg4 >> 16) & 0xffff;
}

static inline uint32_t ffa_feature_intid(struct ffa_value args)
{
	return (uint32_t)args.arg2;
}

static inline uint32_t ffa_fwk_msg(struct ffa_value args)
{
	return (uint32_t)args.arg2;
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
	return (uuid->uuid[0] == 0) && (uuid->uuid[1] == 0) &&
	       (uuid->uuid[2] == 0) && (uuid->uuid[3] == 0);
}

/**
 * Flags to determine the partition properties, as required by
 * FFA_PARTITION_INFO_GET.
 *
 * The values of the flags are specified in table 82 of the FF-A 1.0 EAC
 * specification, "Partition information descriptor, partition properties".
 */
typedef uint32_t ffa_partition_properties_t;

/** Partition property: partition supports receipt of direct requests. */
#define FFA_PARTITION_DIRECT_REQ_RECV 0x1

/** Partition property: partition can send direct requests. */
#define FFA_PARTITION_DIRECT_REQ_SEND 0x2

/** Partition property: partition can send and receive indirect messages. */
#define FFA_PARTITION_INDIRECT_MSG 0x4

/** Partition property: partition can receive notifications. */
#define FFA_PARTITION_NOTIFICATION 0x8

/**
 * Holds information returned for each partition by the FFA_PARTITION_INFO_GET
 * interface.
 * This corresponds to table 13.34 of the FF-A 1.1 BETA0 EAC specification,
 * "Partition information descriptor".
 */
struct ffa_partition_info {
	ffa_vm_id_t vm_id;
	ffa_vcpu_count_t vcpu_count;
	ffa_partition_properties_t properties;
	struct ffa_uuid uuid;
};

/**
 * Create a struct for the "Partition information descriptor" defined for v1.0
 * which can be returned to v1.0 endpoints.
 * This corresponds to table 82 of the FF-A 1.0 EAC specification, "Partition
 * information descriptor".
 */

struct ffa_partition_info_v1_0 {
	ffa_vm_id_t vm_id;
	ffa_vcpu_count_t vcpu_count;
	ffa_partition_properties_t properties;
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
#define FFA_NOTIFICATION_MASK(ID) (UINT64_C(1) << ID)

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
#define FFA_NOTIFICATIONS_LIST_SHIFT(l) (2 * (l - 1) + 12)
#define FFA_NOTIFICATIONS_LIST_SIZE_MASK 0x3U

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

/**
 * A set of contiguous pages which is part of a memory region. This corresponds
 * to table 40 of the FF-A 1.0 EAC specification, "Constituent memory region
 * descriptor".
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
 * A set of pages comprising a memory region. This corresponds to table 39 of
 * the FF-A 1.0 EAC specification, "Composite memory region descriptor".
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
 * This corresponds to table 41 of the FF-A 1.0 EAC specification, "Memory
 * access permissions descriptor".
 */
struct ffa_memory_region_attributes {
	/** The ID of the VM to which the memory is being given or shared. */
	ffa_vm_id_t receiver;
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

#define FFA_MEMORY_REGION_TRANSACTION_TYPE_MASK ((0x3U) << 3)
#define FFA_MEMORY_REGION_TRANSACTION_TYPE_UNSPECIFIED ((0x0U) << 3)
#define FFA_MEMORY_REGION_TRANSACTION_TYPE_SHARE ((0x1U) << 3)
#define FFA_MEMORY_REGION_TRANSACTION_TYPE_LEND ((0x2U) << 3)
#define FFA_MEMORY_REGION_TRANSACTION_TYPE_DONATE ((0x3U) << 3)

#define FFA_MEMORY_REGION_ADDRESS_RANGE_HINT_VALID ((0x1U) << 9)
#define FFA_MEMORY_REGION_ADDRESS_RANGE_HINT_MASK ((0xFU) << 5)

/**
 * This corresponds to table 42 of the FF-A 1.0 EAC specification, "Endpoint
 * memory access descriptor".
 */
struct ffa_memory_access {
	struct ffa_memory_region_attributes receiver_permissions;
	/**
	 * Offset in bytes from the start of the outer `ffa_memory_region` to
	 * an `ffa_composite_memory_region` struct.
	 */
	uint32_t composite_memory_region_offset;
	uint64_t reserved_0;
};

/** The maximum number of recipients a memory region may be sent to. */
#define MAX_MEM_SHARE_RECIPIENTS UINT32_C(2)

/**
 * Information about a set of pages which are being shared. This corresponds to
 * table 45 of the FF-A 1.0 EAC specification, "Lend, donate or share memory
 * transaction descriptor". Note that it is also used for retrieve requests and
 * responses.
 */
struct ffa_memory_region {
	/**
	 * The ID of the VM which originally sent the memory region, i.e. the
	 * owner.
	 */
	ffa_vm_id_t sender;
	ffa_memory_attributes_t attributes;
	/** Reserved field, must be 0. */
	uint8_t reserved_0;
	/** Flags to control behaviour of the transaction. */
	ffa_memory_region_flags_t flags;
	ffa_memory_handle_t handle;
	/**
	 * An implementation defined value associated with the receiver and the
	 * memory region.
	 */
	uint64_t tag;
	/** Reserved field, must be 0. */
	uint32_t reserved_1;
	/**
	 * The number of `ffa_memory_access` entries included in this
	 * transaction.
	 */
	uint32_t receiver_count;
	/**
	 * An array of `receiver_count` endpoint memory access descriptors.
	 * Each one specifies a memory region offset, an endpoint and the
	 * attributes with which this memory region should be mapped in that
	 * endpoint's page table.
	 */
	struct ffa_memory_access receivers[];
};

/**
 * Descriptor used for FFA_MEM_RELINQUISH requests. This corresponds to table
 * 150 of the FF-A 1.0 EAC specification, "Descriptor to relinquish a memory
 * region".
 */
struct ffa_mem_relinquish {
	ffa_memory_handle_t handle;
	ffa_memory_region_flags_t flags;
	uint32_t endpoint_count;
	ffa_vm_id_t endpoints[];
};

/**
 * Gets the `ffa_composite_memory_region` for the given receiver from an
 * `ffa_memory_region`, or NULL if it is not valid.
 */
static inline struct ffa_composite_memory_region *
ffa_memory_region_get_composite(struct ffa_memory_region *memory_region,
				uint32_t receiver_index)
{
	uint32_t offset = memory_region->receivers[receiver_index]
				  .composite_memory_region_offset;

	if (offset == 0) {
		return NULL;
	}

	return (struct ffa_composite_memory_region *)((uint8_t *)memory_region +
						      offset);
}

static inline uint32_t ffa_mem_relinquish_init(
	struct ffa_mem_relinquish *relinquish_request,
	ffa_memory_handle_t handle, ffa_memory_region_flags_t flags,
	ffa_vm_id_t sender)
{
	relinquish_request->handle = handle;
	relinquish_request->flags = flags;
	relinquish_request->endpoint_count = 1;
	relinquish_request->endpoints[0] = sender;
	return sizeof(struct ffa_mem_relinquish) + sizeof(ffa_vm_id_t);
}

/**
 * Endpoint RX/TX descriptor, as defined by Table 13.27 in FF-A v1.1 EAC0.
 * It's used by the Hypervisor to describe the RX/TX buffers mapped by a VM
 * to the SPMC, in order to allow indirect messaging.
 */
struct ffa_endpoint_rx_tx_descriptor {
	ffa_vm_id_t endpoint_id;
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
ffa_enpoint_get_rx_memory_region(struct ffa_endpoint_rx_tx_descriptor *desc)
{
	return (struct ffa_composite_memory_region *)((uintptr_t)desc +
						      desc->rx_offset);
}

static inline struct ffa_composite_memory_region *
ffa_enpoint_get_tx_memory_region(struct ffa_endpoint_rx_tx_descriptor *desc)
{
	return (struct ffa_composite_memory_region *)((uintptr_t)desc +
						      desc->tx_offset);
}

void ffa_memory_access_init_permissions(
	struct ffa_memory_access *receiver, ffa_vm_id_t receiver_id,
	enum ffa_data_access data_access,
	enum ffa_instruction_access instruction_access,
	ffa_memory_receiver_flags_t flags);
uint32_t ffa_memory_region_init_single_receiver(
	struct ffa_memory_region *memory_region, size_t memory_region_max_size,
	ffa_vm_id_t sender, ffa_vm_id_t receiver,
	const struct ffa_memory_region_constituent constituents[],
	uint32_t constituent_count, uint32_t tag,
	ffa_memory_region_flags_t flags, enum ffa_data_access data_access,
	enum ffa_instruction_access instruction_access,
	enum ffa_memory_type type, enum ffa_memory_cacheability cacheability,
	enum ffa_memory_shareability shareability, uint32_t *fragment_length,
	uint32_t *total_length);
uint32_t ffa_memory_region_init(
	struct ffa_memory_region *memory_region, size_t memory_region_max_size,
	ffa_vm_id_t sender, struct ffa_memory_access receivers[],
	uint32_t receiver_count,
	const struct ffa_memory_region_constituent constituents[],
	uint32_t constituent_count, uint32_t tag,
	ffa_memory_region_flags_t flags, enum ffa_memory_type type,
	enum ffa_memory_cacheability cacheability,
	enum ffa_memory_shareability shareability, uint32_t *fragment_length,
	uint32_t *total_length);
uint32_t ffa_memory_retrieve_request_init(
	struct ffa_memory_region *memory_region, ffa_memory_handle_t handle,
	ffa_vm_id_t sender, struct ffa_memory_access receivers[],
	uint32_t receiver_count, uint32_t tag, ffa_memory_region_flags_t flags,
	enum ffa_memory_type type, enum ffa_memory_cacheability cacheability,
	enum ffa_memory_shareability shareability);
uint32_t ffa_memory_retrieve_request_init_single_receiver(
	struct ffa_memory_region *memory_region, ffa_memory_handle_t handle,
	ffa_vm_id_t sender, ffa_vm_id_t receiver, uint32_t tag,
	ffa_memory_region_flags_t flags, enum ffa_data_access data_access,
	enum ffa_instruction_access instruction_access,
	enum ffa_memory_type type, enum ffa_memory_cacheability cacheability,
	enum ffa_memory_shareability shareability);
uint32_t ffa_memory_lender_retrieve_request_init(
	struct ffa_memory_region *memory_region, ffa_memory_handle_t handle,
	ffa_vm_id_t sender);
bool ffa_retrieved_memory_region_init(
	struct ffa_memory_region *response, size_t response_max_size,
	ffa_vm_id_t sender, ffa_memory_attributes_t attributes,
	ffa_memory_region_flags_t flags, ffa_memory_handle_t handle,
	ffa_vm_id_t receiver, ffa_memory_access_permissions_t permissions,
	uint32_t page_count, uint32_t total_constituent_count,
	const struct ffa_memory_region_constituent constituents[],
	uint32_t fragment_constituent_count, uint32_t *total_length,
	uint32_t *fragment_length);
uint32_t ffa_memory_fragment_init(
	struct ffa_memory_region_constituent *fragment,
	size_t fragment_max_size,
	const struct ffa_memory_region_constituent constituents[],
	uint32_t constituent_count, uint32_t *fragment_length);
void ffa_endpoint_rx_tx_descriptor_init(
	struct ffa_endpoint_rx_tx_descriptor *desc, ffa_vm_id_t endpoint_id,
	uint64_t rx_address, uint64_t tx_address);
