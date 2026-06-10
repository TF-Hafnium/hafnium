/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/vm.h"

bool ffa_vm_supports_indirect_messages(struct vm *vm)
{
	return vm->ffa_version >= FFA_VERSION_1_1 &&
	       vm_supports_messaging_method(vm, FFA_PARTITION_INDIRECT_MSG);
}

bool ffa_vm_managed_exit_supported(struct vm *vm)
{
	(void)vm;

	return false;
}

bool ffa_other_world_ffa_in_use(void)
{
	/*
	 * In the Hypervisor build, HF_OTHER_WORLD_ID refers to the secure world
	 * rather than the Hypervisor's non-secure physical FF-A instance, so
	 * the SPMC-side FF-A v1.3 ALP5 D0235 aggregation does not exist here.
	 */
	return false;
}

struct vm_locked ffa_vm_find_locked(ffa_id_t vm_id)
{
	if (vm_id_is_current_world(vm_id) || vm_id == HF_OTHER_WORLD_ID) {
		return vm_find_locked(vm_id);
	}

	return (struct vm_locked){.vm = NULL};
}

struct vm_locked ffa_vm_find_locked_create(ffa_id_t vm_id)
{
	return ffa_vm_find_locked(vm_id);
}

bool ffa_vm_notifications_info_get(	     // NOLINTNEXTLINE
	uint16_t *ids, uint32_t *ids_count,  // NOLINTNEXTLINE
	uint32_t *lists_sizes,		     // NOLINTNEXTLINE
	uint32_t *lists_count, const uint32_t ids_count_max)
{
	(void)ids;
	(void)ids_count;
	(void)lists_sizes;
	(void)lists_count;
	(void)ids_count_max;

	return false;
}

void ffa_vm_nwd_free(struct vm_locked to_destroy_locked)
{
	/* Hypervisor never frees VM structs. */
	(void)to_destroy_locked;
}

void ffa_vm_free_resources(struct vm_locked vm_locked)
{
	(void)vm_locked;
}
