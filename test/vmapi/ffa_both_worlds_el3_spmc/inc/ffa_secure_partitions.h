/*
 * Copyright 2023 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

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

/*
 * Helpers to get services information.
 * Defined with SERVICE_PARTITION_INFO_GET macro.
 */
struct ffa_partition_info* service1(void* recv);
struct ffa_partition_info* service2(void* recv);
