/*
 * Copyright 2023 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "hf/mm.h"

#include "test/hftest.h"
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
#define SERVICE1                                                        \
	(struct ffa_uuid)                                               \
	{                                                               \
		{                                                       \
			0x9458bb2d, 0x353b4ee2, 0xaa25710c, 0x99b73ddc, \
		}                                                       \
	}

#define SERVICE2                                            \
	(struct ffa_uuid)                                   \
	{                                                   \
		{                                           \
			0xa609f132, 0x6b4f, 0x4c14, 0x9489, \
		}                                           \
	}

#define SERVICE3                                                       \
	(struct ffa_uuid)                                              \
	{                                                              \
		{                                                      \
			0x1df938ef, 0xe8b94490, 0x84967204, 0xab77f4a5 \
		}                                                      \
	}

#define SERVICE4                                                       \
	(struct ffa_uuid)                                              \
	{                                                              \
		{                                                      \
			0xd6d78930, 0x6cb26103, 0xda311d35, 0xfc03fced \
		}                                                      \
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
bool service2_is_up_sp(void);
bool service2_is_mp_sp(void);
uint64_t syscounter_read(void);
void waitms(uint64_t ms);
bool sp1_fail_at_boot(void);
bool sp2_fail_at_boot(void);
bool sp3_fail_at_boot(void);
bool service2_is_mp_sp(void);
bool service2_is_el0(void);
void setup_wdog_timer_interrupt(void);
void start_wdog_timer(uint32_t time_ms);
