/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "hf/vm.h"

struct ffa_value plat_ffa_is_notifications_bitmap_access_valid(
	struct vcpu *current, ffa_id_t vm_id);

bool plat_ffa_is_notifications_bind_valid(struct vcpu *current,
					  ffa_id_t sender_id,
					  ffa_id_t receiver_id);
bool plat_ffa_notifications_update_bindings_forward(
	ffa_id_t receiver_id, ffa_id_t sender_id, uint32_t flags,
	ffa_notifications_bitmap_t bitmap, bool is_bind, struct ffa_value *ret);

bool plat_ffa_is_notification_set_valid(struct vcpu *current,
					ffa_id_t sender_id,
					ffa_id_t receiver_id);

bool plat_ffa_notification_set_forward(ffa_id_t sender_vm_id,
				       ffa_id_t receiver_vm_id, uint32_t flags,
				       ffa_notifications_bitmap_t bitmap,
				       struct ffa_value *ret);

bool plat_ffa_is_notification_get_valid(struct vcpu *current,
					ffa_id_t receiver_id, uint32_t flags);

bool plat_ffa_notifications_get_from_sp(struct vm_locked receiver_locked,
					ffa_vcpu_index_t vcpu_id,
					ffa_notifications_bitmap_t *from_sp,
					struct ffa_value *ret);

bool plat_ffa_notifications_get_framework_notifications(
	struct vm_locked receiver_locked, ffa_notifications_bitmap_t *from_fwk,
	uint32_t flags, ffa_vcpu_index_t vcpu_id, struct ffa_value *ret);

/**
 * Creates a bitmap for the VM of the given ID.
 */
struct ffa_value plat_ffa_notifications_bitmap_create(
	ffa_id_t vm_id, ffa_vcpu_count_t vcpu_count);

/**
 * Issues a FFA_NOTIFICATION_BITMAP_CREATE.
 * Returns true if the call goes well, and false if call returns with
 * FFA_ERROR_32.
 */
bool plat_ffa_notifications_bitmap_create_call(ffa_id_t vm_id,
					       ffa_vcpu_count_t vcpu_count);

/**
 * Destroys the notifications bitmap for the given VM ID.
 */
struct ffa_value plat_ffa_notifications_bitmap_destroy(ffa_id_t vm_id);

/**
 * Helper to get the struct notifications, depending on the sender's id.
 */
struct notifications *plat_ffa_vm_get_notifications_senders_world(
	struct vm_locked, ffa_id_t sender_id);

bool plat_ffa_notification_info_get_call(struct ffa_value *ret);

/**
 * Helper to send SRI and safely update `ffa_sri_state`, if there has been
 * a call to FFA_NOTIFICATION_SET, and the SRI has been delayed.
 * To be called at a context switch to the NWd.
 */
void plat_ffa_sri_trigger_if_delayed(struct cpu *cpu);

/**
 * Helper to send SRI and safely update `ffa_sri_state`, if it hasn't been
 * delayed in call to FFA_NOTIFICATION_SET.
 */
void plat_ffa_sri_trigger_not_delayed(struct cpu *cpu);

/**
 * Track that in current CPU there was a notification set with delay SRI flag.
 */
void plat_ffa_sri_set_delayed(struct cpu *cpu);

/**
 * Initialize Schedule Receiver Interrupts needed in the context of
 * notifications support.
 */
void plat_ffa_sri_init(struct cpu *cpu);

void plat_ffa_notification_info_get_forward(uint16_t *ids, uint32_t *ids_count,
					    uint32_t *lists_sizes,
					    uint32_t *lists_count,
					    uint32_t ids_count_max);
