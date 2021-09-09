/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/ffa.h"

#include "hf/ffa_internal.h"
#include "hf/vcpu.h"
#include "hf/vm.h"

struct ffa_value arch_ffa_features(uint32_t function_id)
{
	(void)function_id;
	return ffa_error(FFA_NOT_SUPPORTED);
}

ffa_vm_id_t arch_ffa_spmc_id_get(void)
{
	return HF_SPMC_VM_ID;
}

void plat_ffa_log_init(void)
{
}

bool plat_ffa_is_direct_request_valid(struct vcpu *current,
				      ffa_vm_id_t sender_vm_id,
				      ffa_vm_id_t receiver_vm_id)
{
	(void)current;
	(void)sender_vm_id;
	(void)receiver_vm_id;

	return true;
}

bool plat_ffa_is_direct_response_valid(struct vcpu *current,
				       ffa_vm_id_t sender_vm_id,
				       ffa_vm_id_t receiver_vm_id)
{
	(void)current;
	(void)sender_vm_id;
	(void)receiver_vm_id;

	return true;
}

bool plat_ffa_run_forward(ffa_vm_id_t vm_id, ffa_vcpu_index_t vcpu_idx,
			  struct ffa_value *ret)
{
	(void)vm_id;
	(void)vcpu_idx;
	(void)ret;

	return false;
}

bool plat_ffa_direct_request_forward(ffa_vm_id_t receiver_vm_id,
				     struct ffa_value args,
				     struct ffa_value *ret)
{
	(void)receiver_vm_id;
	(void)args;
	(void)ret;
	return false;
}

ffa_memory_handle_t plat_ffa_memory_handle_make(uint64_t index)
{
	return index;
}

bool plat_ffa_memory_handle_allocated_by_current_world(
	ffa_memory_handle_t handle)
{
	(void)handle;
	return false;
}

bool plat_ffa_is_notifications_bind_valid(struct vcpu *current,
					  ffa_vm_id_t sender_id,
					  ffa_vm_id_t receiver_id)
{
	(void)current;
	(void)sender_id;
	(void)receiver_id;
	return false;
}

bool plat_ffa_notifications_update_bindings_forward(
	ffa_vm_id_t receiver_id, ffa_vm_id_t sender_id, uint32_t flags,
	ffa_notifications_bitmap_t bitmap, bool is_bind, struct ffa_value *ret)
{
	(void)ret;
	(void)receiver_id;
	(void)sender_id;
	(void)flags;
	(void)bitmap;
	(void)is_bind;
	(void)ret;

	return false;
}

ffa_partition_properties_t plat_ffa_partition_properties(
	ffa_vm_id_t current_id, const struct vm *target)
{
	(void)current_id;
	(void)target;
	return 0;
}

bool plat_ffa_vm_managed_exit_supported(struct vm *vm)
{
	(void)vm;
	return false;
}

bool plat_ffa_is_notifications_create_valid(struct vcpu *current,
					    ffa_vm_id_t vm_id)
{
	(void)current;
	(void)vm_id;

	return false;
}

bool plat_ffa_is_notification_set_valid(struct vcpu *current,
					ffa_vm_id_t sender_id,
					ffa_vm_id_t receiver_id)
{
	(void)current;
	(void)sender_id;
	(void)receiver_id;
	return false;
}

bool plat_ffa_is_notification_get_valid(struct vcpu *current,
					ffa_vm_id_t receiver_id)
{
	(void)current;
	(void)receiver_id;
	return false;
}

bool plat_ffa_notifications_get_from_sp(
	struct vm_locked receiver_locked, ffa_vcpu_index_t vcpu_id,
	const ffa_notifications_bitmap_t *from_sp, struct ffa_value *ret)
{
	(void)receiver_locked;
	(void)vcpu_id;
	(void)from_sp;
	(void)ret;

	return false;
}

struct ffa_value plat_ffa_notifications_bitmap_create(
	ffa_vm_id_t vm_id, ffa_vcpu_count_t vcpu_count)
{
	(void)vm_id;
	(void)vcpu_count;

	return ffa_error(FFA_NOT_SUPPORTED);
}

struct ffa_value plat_ffa_notifications_bitmap_destroy(ffa_vm_id_t vm_id)
{
	(void)vm_id;

	return ffa_error(FFA_NOT_SUPPORTED);
}

struct vm_locked plat_ffa_vm_find_locked(ffa_vm_id_t vm_id)
{
	(void)vm_id;
	return (struct vm_locked){.vm = NULL};
}

bool plat_ffa_is_vm_id(ffa_vm_id_t vm_id)
{
	(void)vm_id;
	return false;
}

bool plat_ffa_vm_notifications_info_get(const uint16_t *ids,
					const uint32_t *ids_count,
					const uint32_t *lists_sizes,
					const uint32_t *lists_count,
					const uint32_t ids_count_max)
{
	(void)ids;
	(void)ids_count;
	(void)lists_sizes;
	(void)lists_count;
	(void)ids_count_max;

	return false;
}
