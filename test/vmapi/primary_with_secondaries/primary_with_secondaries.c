/*
 * Copyright 2022 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "vmapi/hf/call.h"
#include "vmapi/hf/ffa.h"

#include "primary_with_secondary.h"
#include "test/hftest.h"
#include "test/vmapi/ffa.h"

SERVICE_PARTITION_INFO_GET(service1, SERVICE1)
SERVICE_PARTITION_INFO_GET(service2, SERVICE2)
SERVICE_PARTITION_INFO_GET(service3, SERVICE3)

/**
 * Helper to setup mailbox for precondition functions.
 */
static struct mailbox_buffers get_precondition_mailbox(void)
{
	static struct mailbox_buffers mb = {.recv = NULL, .send = NULL};

	if (mb.send == NULL && mb.recv == NULL) {
		mb = set_up_mailbox();
	}

	return mb;
}

/*
 * The following is a precondition function, for the current system set-up.
 * This is currently being used to skip memory sharing tests, when
 * the service is an SP.
 */
bool service1_is_vm(void)
{
	struct mailbox_buffers mb = get_precondition_mailbox();
	struct ffa_partition_info *service1_info = service1(mb.recv);
	return IS_VM_ID(service1_info->vm_id);
}

/*
 * The following is a precondition function, for the current system set-up.
 * This is currently being used to skip memory sharing tests, if the SPMC
 * and SPs are present in the secure world. The rationale, is to skip
 * tests that are not doing any world switch. These tests are running in the
 * CI in different setups, with no expected change in coverage.
 */
bool hypervisor_only(void)
{
	/*
	 * Determine only PVM and VMS are deployed by checking we don't retrieve
	 * IDs of endpoints that are not VMs.
	 */
	struct mailbox_buffers mb = get_precondition_mailbox();
	struct ffa_partition_info *endpoint_info = mb.recv;
	struct ffa_uuid uuid;
	struct ffa_value ret;
	static bool executed_before = false;
	static bool is_there_non_vm_endpoints = false;

	/*
	 * Subsequent calls to this function will return the previous
	 * determined result, as it is expected to be the same.
	 */
	if (executed_before) {
		return !is_there_non_vm_endpoints;
	}

	ffa_uuid_init(0, 0, 0, 0, &uuid);

	ret = ffa_partition_info_get(&uuid, 0);

	for (uint32_t i = 0; i < ffa_partition_info_get_count(ret); i++) {
		if (!IS_VM_ID(endpoint_info[i].vm_id)) {
			is_there_non_vm_endpoints = true;
			break;
		}
	}

	executed_before = true;

	ffa_rx_release();

	return !is_there_non_vm_endpoints;
}
