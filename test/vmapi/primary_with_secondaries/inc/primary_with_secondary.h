/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "hf/mm.h"

#include "test/vmapi/ffa.h"

/*
 * FF-A UUIDs related to the test partitions providing test services to the
 * Primary VM. These service partitions can either be SPs or VMs, and should
 * be used only once for either an SP or VM.
 * This allows for the PVM to communicate with the service partition, regardless
 * of the ID, which has a bit related to the security state of the partition.
 * The PVM should use the UUID to retrieve the FF-A ID of the partition, before
 * attempting to communicate with it. Thus, the code for the PVM becomes
 * portable between setups where the test service is either a VM or an SP.
 */
#define PVM                                                     \
	(struct ffa_uuid)                                       \
	{                                                       \
		{                                               \
			0xbdfaab86, 0xe9ee, 0x409a, 0xde614c01, \
		}                                               \
	}

#define SERVICE1                                                        \
	(struct ffa_uuid)                                               \
	{                                                               \
		{                                                       \
			0xb4b5671e, 0x4a904fe1, 0xb81ffb13, 0xdae1dacb, \
		}                                                       \
	}

#define SERVICE2                                               \
	(struct ffa_uuid)                                      \
	{                                                      \
		{                                              \
			0x5d45882e, 0xf637, 0xa720, 0xe8669dc, \
		}                                              \
	}

#define SERVICE2_UUID2                                         \
	(struct ffa_uuid)                                      \
	{                                                      \
		{                                              \
			0x6e56993f, 0x0748, 0xb831, 0xf977aed, \
		}                                              \
	}

#define SERVICE3                                             \
	(struct ffa_uuid)                                    \
	{                                                    \
		{                                            \
			0xcbd4482f, 0xcbab, 0x4dba, 0x0738d, \
		}                                            \
	}
#define SERVICE4                                                       \
	(struct ffa_uuid)                                              \
	{                                                              \
		{                                                      \
			0xd6d78930, 0x6cb26103, 0xda311d35, 0xfc03fced \
		}                                                      \
	}

/**
 * The UUID that partitions with a ns-memory region should have
 * in their uuids. To discover partitions with ns-memory regions
 * in the precondition functions.
 */
#define SERVICE_NS_MEM                                                  \
	(struct ffa_uuid)                                               \
	{                                                               \
		{                                                       \
			0xfed46119, 0xb57c449f, 0xa852c15f, 0xd346b1fc, \
		}                                                       \
	}

/**
 * The UUID that S-EL0 partitions should have in their uuids.
 * To discover S-EL0 partitions in the precondition functions.
 */
#define SERVICE_SEL0                                        \
	(struct ffa_uuid)                                   \
	{                                                   \
		{                                           \
			0x580940fa, 0x7e9d, 0x406f, 0x9aa2, \
		}                                           \
	}

/*
 * Helpers to get services information.
 * Defined with SERVICE_PARTITION_INFO_GET macro.
 */
struct ffa_partition_info* service1(void* recv);
struct ffa_partition_info* service2(void* recv);
struct ffa_partition_info* service3(void* recv);
struct ffa_partition_info* service4(void* recv);

/* Precondition functions for this test setup. */
bool service1_is_vm(void);
bool service1_is_not_vm(void);
bool service1_is_secure(void);
bool service1_and_service2_are_secure(void);
bool service1_service2_and_service3_are_secure(void);
bool all_services_are_secure(void);
bool service1_is_mp_sp(void);
bool service2_is_mp_sp(void);
bool service3_is_mp_sp(void);
bool service1_and_service2_are_mp_sp(void);
bool hypervisor_only(void);
bool service1_has_ns_mem(void);
bool service1_is_sel0(void);
bool service1_has_ns_mem_and_sel1(void);
bool service1_has_ns_mem_and_sel0(void);

#define SERVICE_VM1 (HF_VM_ID_OFFSET + 1)
#define SERVICE_VM2 (HF_VM_ID_OFFSET + 2)
#define SERVICE_VM3 (HF_VM_ID_OFFSET + 3)

#define SELF_INTERRUPT_ID 5
#define EXTERNAL_INTERRUPT_ID_A 7
#define EXTERNAL_INTERRUPT_ID_B 8
#define EXTERNAL_INTERRUPT_ID_C 9

/* Helpers common to the setup. */
bool exception_received(struct ffa_value* run_res, const void* recv_buf);
