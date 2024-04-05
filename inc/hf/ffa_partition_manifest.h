/*
 * Copyright 2023 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include <stdint.h>

#include "hf/addr.h"
#include "hf/memiter.h"
#include "hf/string.h"

#include "vmapi/hf/ffa.h"

#define MANIFEST_INVALID_ADDRESS UINT64_MAX
#define MANIFEST_INVALID_ID UINT32_MAX

#define SP_RTX_BUF_NAME_SIZE 10

/** FF-A manifest memory and device regions attributes. */
#define MANIFEST_REGION_ATTR_READ (UINT32_C(1) << 0)
#define MANIFEST_REGION_ATTR_WRITE (UINT32_C(1) << 1)
#define MANIFEST_REGION_ATTR_EXEC (UINT32_C(1) << 2)
#define MANIFEST_REGION_ATTR_SECURITY (UINT32_C(1) << 3)
#define MANIFEST_REGION_ATTR_MEMORY_TYPE_DEVICE (UINT32_C(1) << 4)

#define MANIFEST_REGION_ALL_ATTR_MASK                                \
	(MANIFEST_REGION_ATTR_READ | MANIFEST_REGION_ATTR_WRITE |    \
	 MANIFEST_REGION_ATTR_EXEC | MANIFEST_REGION_ATTR_SECURITY | \
	 MANIFEST_REGION_ATTR_MEMORY_TYPE_DEVICE)

#define MANIFEST_POWER_MANAGEMENT_CPU_OFF_SUPPORTED (UINT32_C(1) << 0)
#define MANIFEST_POWER_MANAGEMENT_CPU_ON_SUPPORTED (UINT32_C(1) << 3)
#define MANIFEST_POWER_MANAGEMENT_NONE_MASK (UINT32_C(0))
#define MANIFEST_POWER_MANAGEMENT_ALL_MASK             \
	(MANIFEST_POWER_MANAGEMENT_CPU_OFF_SUPPORTED | \
	 MANIFEST_POWER_MANAGEMENT_CPU_ON_SUPPORTED)

/* Highest possible value for the boot-order field. */
#define DEFAULT_BOOT_ORDER 0xFFFF
#define DEFAULT_BOOT_GP_REGISTER UINT32_C(-1)

enum run_time_el {
	EL1 = 0,
	S_EL0,
	S_EL1,
	SUPERVISOR_MODE,
	SECURE_USER_MODE,
	SECURE_SUPERVISOR_MODE,
	EL0
};

enum execution_state { AARCH64 = 0, AARCH32 };

enum xlat_granule { PAGE_4KB = 0, PAGE_16KB, PAGE_64KB };

/**
 * Properties of the DMA capable device upstream of an SMMU as specified in the
 * memory region description of the partition manifest.
 */
struct dma_device_properties {
	/** SMMU ID - optional */
	uint32_t smmu_id;
	/** IMPDEF id tracking DMA peripheral device - optional */
	uint8_t dma_device_id;
	/** Count of Stream IDs assigned to device - optional */
	uint8_t stream_count;
	/** List of Stream IDs assigned to device - optional */
	uint32_t stream_ids[PARTITION_MAX_STREAMS_PER_DEVICE];
	/** Instruction and data access permissions - optional */
	uint32_t dma_access_permissions;
};

/**
 * Partition Memory region as described in FFA v1.2 spec, Table 5.2 along with
 * an implementation defined struct to track the properties of a DMA capable
 * device that has access to this memory region.
 */
struct memory_region {
	struct string name;
	/**
	 * Specify PA, VA for S-EL0 partitions or IPA
	 * for S-EL1 partitions - optional.
	 */
	uintptr_t base_address;
	/** Page count - mandatory */
	uint32_t page_count;
	/** Memory attributes - mandatory */
	uint32_t attributes;
	/** DMA device properties - optional */
	struct dma_device_properties dma_prop;
};

struct interrupt_info {
	uint32_t id;
	uint32_t attributes;
	bool mpidr_valid;
	uint64_t mpidr;
};

/**
 * Partition Device region as described in FFA v1.2 spec, Table 5.3 along with
 * few implementation defined fields.
 */
struct device_region {
	/** Device base PA - mandatory */
	uintptr_t base_address;
	/** Page count - mandatory */
	uint32_t page_count;
	/** Memory attributes - mandatory */
	uint32_t attributes;
	/** List of physical interrupt ID's and their attributes - optional */
	struct interrupt_info interrupts[PARTITION_MAX_INTERRUPTS_PER_DEVICE];
	/** Count of physical interrupts - optional */
	uint8_t interrupt_count;
	/** SMMU ID - optional */
	uint32_t smmu_id;
	/** IMPDEF id tracking DMA peripheral device - optional */
	uint8_t dma_device_id;
	/** Count of Stream IDs assigned to device - optional */
	uint8_t stream_count;
	/** List of Stream IDs assigned to device - optional */
	uint32_t stream_ids[PARTITION_MAX_STREAMS_PER_DEVICE];
	/** Exclusive access to an endpoint - optional */
	bool exclusive_access;
	/** Name of Device region - optional */
	struct string name;
};

/**
 * RX/TX buffer, reference to memory-region entries that describe RX/TX
 * buffers in partition manifest.
 */
struct rx_tx {
	bool available;
	uint32_t rx_phandle;
	uint32_t tx_phandle;
	struct memory_region *rx_buffer;
	struct memory_region *tx_buffer;
};

/**
 * Partition manifest as described in FF-A v1.0 spec section 3.1
 */
struct ffa_partition_manifest {
	/** FF-A expected version - mandatory */
	enum ffa_version ffa_version;
	/** UUID - at least one UUID mandatory */
	uint16_t uuid_count;
	struct ffa_uuid uuids[PARTITION_MAX_UUIDS];
	/** Partition id - optional */
	ffa_id_t id;
	/** Aux ids for mem transactions - optional */
	ffa_id_t aux_id;

	/* NOTE: optional name field maps to VM debug_name field */

	/** mandatory */
	ffa_vcpu_count_t execution_ctx_count;
	/** EL1 or secure EL1, secure EL0 - mandatory */
	enum run_time_el run_time_el;
	/** AArch32 / AArch64 - mandatory */
	enum execution_state execution_state;
	/** optional */
	uintpaddr_t load_addr;
	/** optional */
	size_t ep_offset;
	/**  4/16/64KB - optional */
	enum xlat_granule xlat_granule;
	/** Register id from w0/x0-w3/x3 - optional. */
	uint32_t gp_register_num;
	/**
	 *  Flags the presence of the optional IMPDEF node to define Partition's
	 *  Boot Info.
	 */
	bool boot_info;
	/** optional */
	uint16_t boot_order;

	/** Optional RX/TX buffers */
	struct rx_tx rxtx;

	/** mandatory - direct/indirect msg or both */
	uint16_t messaging_method;
	/** mandatory - action in response to non secure interrupt */
	uint8_t ns_interrupts_action;
	/** optional - managed exit signaled through vIRQ */
	bool me_signal_virq;
	/** optional - receipt of notifications. */
	bool notification_support;
	/**
	 * optional - power management messages bitfield.
	 *
	 * See [1] power-management-messages manifest field.
	 *
	 * The Hafnium supported combinations for a MP SP are:
	 * Bit 0 - relay PSCI cpu off message to the SP.
	 * Bit 3 - relay PSCI cpu on to the SP.
	 *
	 * [1]
	 * https://trustedfirmware-a.readthedocs.io/en/latest/components/ffa-manifest-binding.html#partition-properties
	 */
	uint32_t power_management;
	/** optional */
	bool has_primary_scheduler;
	/** optional - tuples SEPID/SMMUID/streamId */
	uint32_t stream_ep_ids[1];

	/** Memory regions */
	uint16_t mem_region_count;
	struct memory_region mem_regions[PARTITION_MAX_MEMORY_REGIONS];
	/** Device regions */
	uint16_t dev_region_count;
	struct device_region dev_regions[PARTITION_MAX_DEVICE_REGIONS];
	/** DMA device count. */
	uint8_t dma_device_count;

	/** optional - action in response to Other-Secure interrupt */
	uint8_t other_s_interrupts_action;
};
