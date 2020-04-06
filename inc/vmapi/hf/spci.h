/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include "hf/types.h"

/* clang-format off */

#define SPCI_LOW_32_ID  0x84000060
#define SPCI_HIGH_32_ID 0x8400007F
#define SPCI_LOW_64_ID  0xC4000060
#define SPCI_HIGH_32_ID 0x8400007F

/* SPCI function identifiers. */
#define SPCI_ERROR_32                 0x84000060
#define SPCI_SUCCESS_32               0x84000061
#define SPCI_INTERRUPT_32             0x84000062
#define SPCI_VERSION_32               0x84000063
#define SPCI_FEATURES_32              0x84000064
#define SPCI_RX_RELEASE_32            0x84000065
#define SPCI_RXTX_MAP_32              0x84000066
#define SPCI_RXTX_MAP_64              0xC4000066
#define SPCI_RXTX_UNMAP_32            0x84000067
#define SPCI_PARTITION_INFO_GET_32    0x84000068
#define SPCI_ID_GET_32                0x84000069
#define SPCI_MSG_POLL_32              0x8400006A
#define SPCI_MSG_WAIT_32              0x8400006B
#define SPCI_YIELD_32                 0x8400006C
#define SPCI_RUN_32                   0x8400006D
#define SPCI_MSG_SEND_32              0x8400006E
#define SPCI_MSG_SEND_DIRECT_REQ_32   0x8400006F
#define SPCI_MSG_SEND_DIRECT_RESP_32  0x84000070
#define SPCI_MEM_DONATE_32            0x84000071
#define SPCI_MEM_LEND_32              0x84000072
#define SPCI_MEM_SHARE_32             0x84000073
#define SPCI_MEM_RETRIEVE_REQ_32      0x84000074
#define SPCI_MEM_RETRIEVE_RESP_32     0x84000075
#define SPCI_MEM_RELINQUISH_32        0x84000076
#define SPCI_MEM_RECLAIM_32           0x84000077

/* SPCI error codes. */
#define SPCI_NOT_SUPPORTED      INT32_C(-1)
#define SPCI_INVALID_PARAMETERS INT32_C(-2)
#define SPCI_NO_MEMORY          INT32_C(-3)
#define SPCI_BUSY               INT32_C(-4)
#define SPCI_INTERRUPTED        INT32_C(-5)
#define SPCI_DENIED             INT32_C(-6)
#define SPCI_RETRY              INT32_C(-7)
#define SPCI_ABORTED            INT32_C(-8)

/* clang-format on */

/* SPCI function specific constants. */
#define SPCI_MSG_RECV_BLOCK 0x1
#define SPCI_MSG_RECV_BLOCK_MASK 0x1

#define SPCI_MSG_SEND_NOTIFY 0x1
#define SPCI_MSG_SEND_NOTIFY_MASK 0x1

#define SPCI_MEM_RECLAIM_CLEAR 0x1

#define SPCI_SLEEP_INDEFINITE 0

/**
 * For use where the SPCI specification refers explicitly to '4K pages'. Not to
 * be confused with PAGE_SIZE, which is the translation granule Hafnium is
 * configured to use.
 */
#define SPCI_PAGE_SIZE 4096

/* The maximum length possible for a single message. */
#define SPCI_MSG_PAYLOAD_MAX HF_MAILBOX_SIZE

enum spci_data_access {
	SPCI_DATA_ACCESS_NOT_SPECIFIED,
	SPCI_DATA_ACCESS_RO,
	SPCI_DATA_ACCESS_RW,
	SPCI_DATA_ACCESS_RESERVED,
};

enum spci_instruction_access {
	SPCI_INSTRUCTION_ACCESS_NOT_SPECIFIED,
	SPCI_INSTRUCTION_ACCESS_NX,
	SPCI_INSTRUCTION_ACCESS_X,
	SPCI_INSTRUCTION_ACCESS_RESERVED,
};

enum spci_memory_type {
	SPCI_MEMORY_NOT_SPECIFIED_MEM,
	SPCI_MEMORY_DEVICE_MEM,
	SPCI_MEMORY_NORMAL_MEM,
};

enum spci_memory_cacheability {
	SPCI_MEMORY_CACHE_RESERVED = 0x0,
	SPCI_MEMORY_CACHE_NON_CACHEABLE = 0x1,
	SPCI_MEMORY_CACHE_RESERVED_1 = 0x2,
	SPCI_MEMORY_CACHE_WRITE_BACK = 0x3,
	SPCI_MEMORY_DEV_NGNRNE = 0x0,
	SPCI_MEMORY_DEV_NGNRE = 0x1,
	SPCI_MEMORY_DEV_NGRE = 0x2,
	SPCI_MEMORY_DEV_GRE = 0x3,
};

enum spci_memory_shareability {
	SPCI_MEMORY_SHARE_NON_SHAREABLE,
	SPCI_MEMORY_SHARE_RESERVED,
	SPCI_MEMORY_OUTER_SHAREABLE,
	SPCI_MEMORY_INNER_SHAREABLE,
};

typedef uint8_t spci_memory_access_permissions_t;

/**
 * This corresponds to table 44 of the FF-A 1.0 EAC specification, "Memory
 * region attributes descriptor".
 */
typedef uint8_t spci_memory_attributes_t;

#define SPCI_DATA_ACCESS_OFFSET (0x0U)
#define SPCI_DATA_ACCESS_MASK ((0x3U) << SPCI_DATA_ACCESS_OFFSET)

#define SPCI_INSTRUCTION_ACCESS_OFFSET (0x2U)
#define SPCI_INSTRUCTION_ACCESS_MASK ((0x3U) << SPCI_INSTRUCTION_ACCESS_OFFSET)

#define SPCI_MEMORY_TYPE_OFFSET (0x4U)
#define SPCI_MEMORY_TYPE_MASK ((0x3U) << SPCI_MEMORY_TYPE_OFFSET)

#define SPCI_MEMORY_CACHEABILITY_OFFSET (0x2U)
#define SPCI_MEMORY_CACHEABILITY_MASK \
	((0x3U) << SPCI_MEMORY_CACHEABILITY_OFFSET)

#define SPCI_MEMORY_SHAREABILITY_OFFSET (0x0U)
#define SPCI_MEMORY_SHAREABILITY_MASK \
	((0x3U) << SPCI_MEMORY_SHAREABILITY_OFFSET)

#define ATTR_FUNCTION_SET(name, container_type, offset, mask)                  \
	static inline void spci_set_##name##_attr(container_type *attr,        \
						  const enum spci_##name perm) \
	{                                                                      \
		*attr = (*attr & ~(mask)) | ((perm << offset) & mask);         \
	}

#define ATTR_FUNCTION_GET(name, container_type, offset, mask)       \
	static inline enum spci_##name spci_get_##name##_attr(      \
		container_type attr)                                \
	{                                                           \
		return (enum spci_##name)((attr & mask) >> offset); \
	}

ATTR_FUNCTION_SET(data_access, spci_memory_access_permissions_t,
		  SPCI_DATA_ACCESS_OFFSET, SPCI_DATA_ACCESS_MASK)
ATTR_FUNCTION_GET(data_access, spci_memory_access_permissions_t,
		  SPCI_DATA_ACCESS_OFFSET, SPCI_DATA_ACCESS_MASK)

ATTR_FUNCTION_SET(instruction_access, spci_memory_access_permissions_t,
		  SPCI_INSTRUCTION_ACCESS_OFFSET, SPCI_INSTRUCTION_ACCESS_MASK)
ATTR_FUNCTION_GET(instruction_access, spci_memory_access_permissions_t,
		  SPCI_INSTRUCTION_ACCESS_OFFSET, SPCI_INSTRUCTION_ACCESS_MASK)

ATTR_FUNCTION_SET(memory_type, spci_memory_attributes_t,
		  SPCI_MEMORY_TYPE_OFFSET, SPCI_MEMORY_TYPE_MASK)
ATTR_FUNCTION_GET(memory_type, spci_memory_attributes_t,
		  SPCI_MEMORY_TYPE_OFFSET, SPCI_MEMORY_TYPE_MASK)

ATTR_FUNCTION_SET(memory_cacheability, spci_memory_attributes_t,
		  SPCI_MEMORY_CACHEABILITY_OFFSET,
		  SPCI_MEMORY_CACHEABILITY_MASK)
ATTR_FUNCTION_GET(memory_cacheability, spci_memory_attributes_t,
		  SPCI_MEMORY_CACHEABILITY_OFFSET,
		  SPCI_MEMORY_CACHEABILITY_MASK)

ATTR_FUNCTION_SET(memory_shareability, spci_memory_attributes_t,
		  SPCI_MEMORY_SHAREABILITY_OFFSET,
		  SPCI_MEMORY_SHAREABILITY_MASK)
ATTR_FUNCTION_GET(memory_shareability, spci_memory_attributes_t,
		  SPCI_MEMORY_SHAREABILITY_OFFSET,
		  SPCI_MEMORY_SHAREABILITY_MASK)

#define SPCI_MEMORY_HANDLE_ALLOCATOR_MASK \
	((spci_memory_handle_t)(UINT64_C(1) << 63))
#define SPCI_MEMORY_HANDLE_ALLOCATOR_HYPERVISOR \
	((spci_memory_handle_t)(UINT64_C(1) << 63))

/** The ID of a VM. These are assigned sequentially starting with an offset. */
typedef uint16_t spci_vm_id_t;

/**
 * A globally-unique ID assigned by the hypervisor for a region of memory being
 * sent between VMs.
 */
typedef uint64_t spci_memory_handle_t;

/**
 * A count of VMs. This has the same range as the VM IDs but we give it a
 * different name to make the different semantics clear.
 */
typedef spci_vm_id_t spci_vm_count_t;

/** The index of a vCPU within a particular VM. */
typedef uint16_t spci_vcpu_index_t;

/**
 * A count of vCPUs. This has the same range as the vCPU indices but we give it
 * a different name to make the different semantics clear.
 */
typedef spci_vcpu_index_t spci_vcpu_count_t;

/** Parameter and return type of SPCI functions. */
struct spci_value {
	uint64_t func;
	uint64_t arg1;
	uint64_t arg2;
	uint64_t arg3;
	uint64_t arg4;
	uint64_t arg5;
	uint64_t arg6;
	uint64_t arg7;
};

static inline spci_vm_id_t spci_msg_send_sender(struct spci_value args)
{
	return (args.arg1 >> 16) & 0xffff;
}

static inline spci_vm_id_t spci_msg_send_receiver(struct spci_value args)
{
	return args.arg1 & 0xffff;
}

static inline uint32_t spci_msg_send_size(struct spci_value args)
{
	return args.arg3;
}

static inline uint32_t spci_msg_send_attributes(struct spci_value args)
{
	return args.arg4;
}

static inline spci_memory_handle_t spci_mem_success_handle(
	struct spci_value args)
{
	return args.arg2;
}

static inline spci_vm_id_t spci_vm_id(struct spci_value args)
{
	return (args.arg1 >> 16) & 0xffff;
}

static inline spci_vcpu_index_t spci_vcpu_index(struct spci_value args)
{
	return args.arg1 & 0xffff;
}

static inline uint64_t spci_vm_vcpu(spci_vm_id_t vm_id,
				    spci_vcpu_index_t vcpu_index)
{
	return ((uint32_t)vm_id << 16) | vcpu_index;
}

/**
 * A set of contiguous pages which is part of a memory region. This corresponds
 * to table 40 of the FF-A 1.0 EAC specification, "Constituent memory region
 * descriptor".
 */
struct spci_memory_region_constituent {
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
struct spci_composite_memory_region {
	/**
	 * The total number of 4 kiB pages included in this memory region. This
	 * must be equal to the sum of page counts specified in each
	 * `spci_memory_region_constituent`.
	 */
	uint32_t page_count;
	/**
	 * The number of constituents (`spci_memory_region_constituent`)
	 * included in this memory region range.
	 */
	uint32_t constituent_count;
	/** Reserved field, must be 0. */
	uint64_t reserved_0;
	/** An array of `constituent_count` memory region constituents. */
	struct spci_memory_region_constituent constituents[];
};

/** Flags to indicate properties of receivers during memory region retrieval. */
typedef uint8_t spci_memory_receiver_flags_t;

/**
 * This corresponds to table 41 of the FF-A 1.0 EAC specification, "Memory
 * access permissions descriptor".
 */
struct spci_memory_region_attributes {
	/** The ID of the VM to which the memory is being given or shared. */
	spci_vm_id_t receiver;
	/**
	 * The permissions with which the memory region should be mapped in the
	 * receiver's page table.
	 */
	spci_memory_access_permissions_t permissions;
	/**
	 * Flags used during SPCI_MEM_RETRIEVE_REQ and SPCI_MEM_RETRIEVE_RESP
	 * for memory regions with multiple borrowers.
	 */
	spci_memory_receiver_flags_t flags;
};

/** Flags to control the behaviour of a memory sharing transaction. */
typedef uint32_t spci_memory_region_flags_t;

/**
 * Clear memory region contents after unmapping it from the sender and before
 * mapping it for any receiver.
 */
#define SPCI_MEMORY_REGION_FLAG_CLEAR 0x1

/**
 * Whether the hypervisor may time slice the memory sharing or retrieval
 * operation.
 */
#define SPCI_MEMORY_REGION_FLAG_TIME_SLICE 0x2

/**
 * Whether the hypervisor should clear the memory region after the receiver
 * relinquishes it or is aborted.
 */
#define SPCI_MEMORY_REGION_FLAG_CLEAR_RELINQUISH 0x4

#define SPCI_MEMORY_REGION_TRANSACTION_TYPE_MASK ((0x3U) << 3)
#define SPCI_MEMORY_REGION_TRANSACTION_TYPE_UNSPECIFIED ((0x0U) << 3)
#define SPCI_MEMORY_REGION_TRANSACTION_TYPE_SHARE ((0x1U) << 3)
#define SPCI_MEMORY_REGION_TRANSACTION_TYPE_LEND ((0x2U) << 3)
#define SPCI_MEMORY_REGION_TRANSACTION_TYPE_DONATE ((0x3U) << 3)

/**
 * This corresponds to table 42 of the FF-A 1.0 EAC specification, "Endpoint
 * memory access descriptor".
 */
struct spci_memory_access {
	struct spci_memory_region_attributes receiver_permissions;
	/**
	 * Offset in bytes from the start of the outer `spci_memory_region` to
	 * an `spci_composite_memory_region` struct.
	 */
	uint32_t composite_memory_region_offset;
	uint64_t reserved_0;
};

/**
 * Information about a set of pages which are being shared. This corresponds to
 * table 45 of the FF-A 1.0 EAC specification, "Lend, donate or share memory
 * transaction descriptor". Note that it is also used for retrieve requests and
 * responses.
 */
struct spci_memory_region {
	/**
	 * The ID of the VM which originally sent the memory region, i.e. the
	 * owner.
	 */
	spci_vm_id_t sender;
	spci_memory_attributes_t attributes;
	/** Reserved field, must be 0. */
	uint8_t reserved_0;
	/** Flags to control behaviour of the transaction. */
	spci_memory_region_flags_t flags;
	spci_memory_handle_t handle;
	/**
	 * An implementation defined value associated with the receiver and the
	 * memory region.
	 */
	uint64_t tag;
	/** Reserved field, must be 0. */
	uint32_t reserved_1;
	/**
	 * The number of `spci_memory_access` entries included in this
	 * transaction.
	 */
	uint32_t receiver_count;
	/**
	 * An array of `attribute_count` endpoint memory access descriptors.
	 * Each one specifies a memory region offset, an endpoint and the
	 * attributes with which this memory region should be mapped in that
	 * endpoint's page table.
	 */
	struct spci_memory_access receivers[];
};

/**
 * Descriptor used for SPCI_MEM_RELINQUISH requests. This corresponds to table
 * 150 of the FF-A 1.0 EAC specification, "Descriptor to relinquish a memory
 * region".
 */
struct spci_mem_relinquish {
	spci_memory_handle_t handle;
	spci_memory_region_flags_t flags;
	uint32_t endpoint_count;
	spci_vm_id_t endpoints[];
};

/**
 * Gets the `spci_composite_memory_region` for the given receiver from an
 * `spci_memory_region`, or NULL if it is not valid.
 */
static inline struct spci_composite_memory_region *
spci_memory_region_get_composite(struct spci_memory_region *memory_region,
				 uint32_t receiver_index)
{
	uint32_t offset = memory_region->receivers[receiver_index]
				  .composite_memory_region_offset;

	if (offset == 0) {
		return NULL;
	}

	return (struct spci_composite_memory_region *)((uint8_t *)
							       memory_region +
						       offset);
}

static inline uint32_t spci_mem_relinquish_init(
	struct spci_mem_relinquish *relinquish_request,
	spci_memory_handle_t handle, spci_memory_region_flags_t flags,
	spci_vm_id_t sender)
{
	relinquish_request->handle = handle;
	relinquish_request->flags = flags;
	relinquish_request->endpoint_count = 1;
	relinquish_request->endpoints[0] = sender;
	return sizeof(struct spci_mem_relinquish) + sizeof(spci_vm_id_t);
}

uint32_t spci_memory_region_init(
	struct spci_memory_region *memory_region, spci_vm_id_t sender,
	spci_vm_id_t receiver,
	const struct spci_memory_region_constituent constituents[],
	uint32_t constituent_count, uint32_t tag,
	spci_memory_region_flags_t flags, enum spci_data_access data_access,
	enum spci_instruction_access instruction_access,
	enum spci_memory_type type, enum spci_memory_cacheability cacheability,
	enum spci_memory_shareability shareability);
uint32_t spci_memory_retrieve_request_init(
	struct spci_memory_region *memory_region, spci_memory_handle_t handle,
	spci_vm_id_t sender, spci_vm_id_t receiver, uint32_t tag,
	spci_memory_region_flags_t flags, enum spci_data_access data_access,
	enum spci_instruction_access instruction_access,
	enum spci_memory_type type, enum spci_memory_cacheability cacheability,
	enum spci_memory_shareability shareability);
uint32_t spci_retrieved_memory_region_init(
	struct spci_memory_region *response, size_t response_max_size,
	spci_vm_id_t sender, spci_memory_attributes_t attributes,
	spci_memory_region_flags_t flags, spci_memory_handle_t handle,
	spci_vm_id_t receiver, spci_memory_access_permissions_t permissions,
	const struct spci_memory_region_constituent constituents[],
	uint32_t constituent_count);
