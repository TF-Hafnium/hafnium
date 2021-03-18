/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "hf/ffa.h"
#include "hf/vcpu.h"
#include "hf/vm.h"

/** Returns the SPMC ID. */
struct ffa_value plat_ffa_spmc_id_get(void);

void plat_ffa_log_init(void);
void plat_ffa_init(bool tee_enabled);
bool plat_ffa_is_direct_request_valid(struct vcpu *current,
				      ffa_vm_id_t sender_vm_id,
				      ffa_vm_id_t receiver_vm_id);
bool plat_ffa_is_direct_response_valid(struct vcpu *current,
				       ffa_vm_id_t sender_vm_id,
				       ffa_vm_id_t receiver_vm_id);
bool plat_ffa_direct_request_forward(ffa_vm_id_t receiver_vm_id,
				     struct ffa_value args,
				     struct ffa_value *ret);
bool plat_ffa_is_notifications_create_valid(struct vcpu *current,
					    ffa_vm_id_t vm_id);

bool plat_ffa_is_notifications_bind_valid(struct vcpu *current,
					  ffa_vm_id_t sender_id,
					  ffa_vm_id_t receiver_id);

/**
 * Checks whether managed exit is supported by given SP.
 */
bool plat_ffa_vm_managed_exit_supported(struct vm *vm);

/**
 * Encodes memory handle according to section 5.10.2 of the FF-A v1.0 spec.
 */
ffa_memory_handle_t plat_ffa_memory_handle_make(uint64_t index);

/**
 * Checks whether given handle was allocated by current world, according to
 * handle encoding rules.
 */
bool plat_ffa_memory_handle_allocated_by_current_world(
	ffa_memory_handle_t handle);

/**
 * Return the FF-A partition info VM/SP properties given the VM id.
 */
ffa_partition_properties_t plat_ffa_partition_properties(
	ffa_vm_id_t current_id, const struct vm *target);

/**
 * Initializes the NWd VM structures for Notifications support.
 */
void plat_ffa_vm_init(void);

/**
 * Get NWd VM's structure.
 */
struct vm_locked plat_ffa_vm_find_locked(ffa_vm_id_t vm_id);

/**
 * Creates a bitmap for the VM of the given ID.
 */
struct ffa_value plat_ffa_notifications_bitmap_create(
	ffa_vm_id_t vm_id, ffa_vcpu_count_t vcpu_count);

/**
 * Destroys the notifications bitmap for the given VM ID.
 */
struct ffa_value plat_ffa_notifications_bitmap_destroy(ffa_vm_id_t vm_id);

/**
 * Helper to get the struct notifications, depending on the sender's id.
 */
struct notifications *plat_ffa_vm_get_notifications_senders_world(
	struct vm_locked vm_locked, ffa_vm_id_t sender_id);

/**
 * Helper to check if FF-A ID is a VM ID.
 */
bool plat_ffa_is_vm_id(ffa_vm_id_t vm_id);
