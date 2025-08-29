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
#include "test/vmapi/arch/exception_handler.h"
#include "test/vmapi/ffa.h"

SERVICE_PARTITION_INFO_GET(service1, SERVICE1)
SERVICE_PARTITION_INFO_GET(service2, SERVICE2)
SERVICE_PARTITION_INFO_GET(service3, SERVICE3)
SERVICE_PARTITION_INFO_GET(service4, SERVICE4)

/**
 * This function serves to identify if test partitions support
 * specific features for a given test. Partition manifest need to
 * be maintained to have the uuid to identify the given test
 * functionality.
 */
bool ffa_partition_id_supports_service(void *recv, ffa_id_t id,
				       struct ffa_uuid *to_check)
{
	bool success = false;
	struct ffa_value ret;
	const struct ffa_partition_info *partitions = recv;
	ffa_vm_count_t vm_count;

	/* Get all partitions that have a given UUID in their manifest. */
	ret = ffa_partition_info_get(to_check, 0);

	if (ret.func == FFA_ERROR_32) {
		return false;
	}

	vm_count = ret.arg2;

	for (uint16_t index = 0; index < vm_count; ++index) {
		if (partitions[index].vm_id == id) {
			success = true;
			break;
		}
	}

	ffa_rx_release();

	return success;
}

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

bool service1_is_secure(void)
{
	struct mailbox_buffers mb = get_precondition_mailbox();
	struct ffa_partition_info *service1_info = service1(mb.recv);

	return !ffa_is_vm_id(service1_info->vm_id);
}

bool service1_and_service2_are_secure(void)
{
	struct mailbox_buffers mb = get_precondition_mailbox();
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_partition_info *service2_info = service2(mb.recv);

	return !ffa_is_vm_id(service1_info->vm_id) &&
	       !ffa_is_vm_id(service2_info->vm_id);
}

bool service1_service2_and_service3_are_secure(void)
{
	struct mailbox_buffers mb = get_precondition_mailbox();
	struct ffa_partition_info *service1_info = service1(mb.recv);
	struct ffa_partition_info *service2_info = service2(mb.recv);
	struct ffa_partition_info *service3_info = service3(mb.recv);

	return !ffa_is_vm_id(service1_info->vm_id) &&
	       !ffa_is_vm_id(service2_info->vm_id) &&
	       !ffa_is_vm_id(service3_info->vm_id);
}

/*
 * The following is a precondition function, for the current system set-up.
 * Check that all services are secure.
 */
bool all_services_are_secure(void)
{
	struct mailbox_buffers mb = get_precondition_mailbox();
	const struct ffa_partition_info *partitions = mb.recv;
	ffa_vm_count_t vm_count;
	const struct ffa_uuid nil_uuid = {{0, 0, 0, 0}};
	const ffa_id_t own_id = hf_vm_get_id();
	bool success = true;
	struct ffa_value ret;

	/* Get all partitions that have a given UUID in their manifest. */
	ret = ffa_partition_info_get(&nil_uuid, 0);

	if (ret.func == FFA_ERROR_32) {
		return false;
	}

	vm_count = ret.arg2;

	for (uint16_t index = 0; index < vm_count; ++index) {
		if (partitions[index].vm_id == own_id) {
			continue;
		}

		if (ffa_is_vm_id(partitions[index].vm_id)) {
			success = false;
			break;
		}
	}

	ffa_rx_release();

	return success;
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

	return ffa_is_vm_id(service1_info->vm_id);
}

/*
 * The following is a precondition function, for the current system set-up.
 * This is currently being used to skip memory sharing tests, when
 * the service2 is an SP.
 */
bool service2_is_vm(void)
{
	struct mailbox_buffers mb = get_precondition_mailbox();
	struct ffa_partition_info *service2_info = service2(mb.recv);

	return ffa_is_vm_id(service2_info->vm_id);
}

/*
 * The following is a precondition function, for the current system set-up.
 * This is currently being used to skip tests, when the service3 is a VM.
 */
bool service3_is_vm(void)
{
	struct mailbox_buffers mb = get_precondition_mailbox();
	struct ffa_partition_info *service3_info = service3(mb.recv);

	return ffa_is_vm_id(service3_info->vm_id);
}

/*
 * The following is a precondition function, for the current system set-up.
 * Check that service1 partition is an SP.
 */
bool service1_is_not_vm(void)
{
	return !service1_is_vm();
}

/*
 * The following is a precondition function, for the current system set-up.
 * Check that service2 partition is an SP.
 */
bool service2_is_not_vm(void)
{
	return !service2_is_vm();
}

/*
 * The following is a precondition function, for the current system set-up.
 * Check that service3 partition is an SP.
 */
bool service3_is_not_vm(void)
{
	return !service3_is_vm();
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
		if (!ffa_is_vm_id(endpoint_info[i].vm_id)) {
			is_there_non_vm_endpoints = true;
			break;
		}
	}

	executed_before = true;

	ffa_rx_release();

	return !is_there_non_vm_endpoints;
}

/*
 * Returns true if the receiver has been preempted by an exception:
 * - if the receiver is an EL1 partition, it should have sent the exception
 * count in a message.
 * - if the receiver is an EL0 partition, the Hyp/SPMC should return FFA_ERROR
 * with error code FFA_ABORTED.
 */
bool exception_received(struct ffa_value *run_res, const void *recv_buf)
{
	return exception_handler_receive_exception_count(recv_buf) == 1 ||
	       (run_res->func == FFA_ERROR_32 &&
		ffa_error_code(*run_res) == FFA_ABORTED);
}

/*
 * The following is a precondition function, for the current system set-up.
 * Check that service1 partition is MP.
 */
bool service1_is_mp(void)
{
	struct mailbox_buffers mb = get_precondition_mailbox();
	struct ffa_partition_info *service1_info = service1(mb.recv);

	return (service1_info->vcpu_count > 1);
}

/*
 * The following is a precondition function, for the current system set-up.
 * Check that service2 partition is an MP SP.
 */
bool service2_is_mp(void)
{
	struct mailbox_buffers mb = get_precondition_mailbox();
	struct ffa_partition_info *service2_info = service2(mb.recv);

	return (service2_info->vcpu_count > 1);
}

/*
 * The following is a precondition function, for the current system set-up.
 * Check that service3 partition is an MP SP.
 */
bool service3_is_mp(void)
{
	struct mailbox_buffers mb = get_precondition_mailbox();
	struct ffa_partition_info *service3_info = service3(mb.recv);

	return (service3_info->vcpu_count > 1);
}

/*
 * The following is a precondition function, for the current system set-up.
 * Check that service1 partition is an MP SP.
 */
bool service1_is_mp_sp(void)
{
	return service1_is_not_vm() && service1_is_mp();
}

/*
 * The following is a precondition function, for the current system set-up.
 * Check that service2 partition is an MP SP.
 */
bool service2_is_mp_sp(void)
{
	return service2_is_not_vm() && service2_is_mp();
}

/*
 * The following is a precondition function, for the current system set-up.
 * Check that service3 partition is an MP SP.
 */
bool service3_is_mp_sp(void)
{
	return service3_is_not_vm() && service3_is_mp();
}

/*
 * The following is a precondition function, for the current system set-up.
 * Check that service1 and service2 partitions are MP SPs.
 */
bool service1_and_service2_are_mp_sp(void)
{
	return service1_is_mp_sp() && service2_is_mp_sp();
}

/*
 * The following is a precondition function, for the current system set-up.
 * Check that service1 has a non-secure memory region.
 */
bool service1_has_ns_mem(void)
{
	struct mailbox_buffers mb = get_precondition_mailbox();
	struct ffa_partition_info *service1_info = service1(mb.recv);

	return ffa_partition_id_supports_service(mb.recv, service1_info->vm_id,
						 &SERVICE_NS_MEM);
}

/*
 * The following is a precondition function, for the current system set-up.
 * Check that service1 is an S-EL0 partition.
 */
bool service1_is_sel0(void)
{
	struct mailbox_buffers mb = get_precondition_mailbox();
	struct ffa_partition_info *service1_info = service1(mb.recv);

	return ffa_partition_id_supports_service(mb.recv, service1_info->vm_id,
						 &SERVICE_SEL0);
}

/*
 * The following is a precondition function, for the current system set-up.
 * Check that service1 has a non-secure memory region and is an S-EL1
 * partition.
 */
bool service1_has_ns_mem_and_sel1(void)
{
	return service1_has_ns_mem() && !service1_is_sel0();
}

/*
 * The following is a precondition function, for the current system set-up.
 * Check that service1 has a non-secure memory region and is an S-EL0
 * partition.
 */
bool service1_has_ns_mem_and_sel0(void)
{
	return service1_has_ns_mem() && service1_is_sel0();
}
