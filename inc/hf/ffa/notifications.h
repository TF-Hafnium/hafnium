/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "hf/ffa.h"
#include "hf/vm.h"

struct ffa_value ffa_notifications_is_bitmap_access_valid(struct vcpu *current,
							  ffa_id_t vm_id);

bool ffa_notifications_is_bind_valid(struct vcpu *current, ffa_id_t sender_id,
				     ffa_id_t receiver_id);
bool ffa_notifications_update_bindings_forward(
	ffa_id_t receiver_id, ffa_id_t sender_id,
	ffa_notification_flags_t flags, ffa_notifications_bitmap_t bitmap,
	bool is_bind, struct ffa_value *ret);

/* Forwarding helpers for v1.3 extended notification ABIs. */
bool ffa_notifications_update_bindings2_forward(
	ffa_id_t receiver_id, ffa_id_t sender_id, uint64_t flags,
	ffa_notifications_bitmap_t bitmap, bool is_bind, struct ffa_value *ret);

bool ffa_notifications_is_set_valid(struct vcpu *current, ffa_id_t sender_id,
				    ffa_id_t receiver_id);

bool ffa_notifications_set_forward(ffa_id_t sender_vm_id,
				   ffa_id_t receiver_vm_id,
				   ffa_notification_flags_t flags,
				   ffa_notifications_bitmap_t bitmap,
				   struct ffa_value *ret);

bool ffa_notifications_set2_forward(struct ffa_value request,
				    struct ffa_value *ret);

bool ffa_notifications_is_get_valid(struct vcpu *current, ffa_id_t receiver_id,
				    ffa_notification_flags_t flags);

struct ffa_value ffa_notifications_get_from_sp(
	struct vm_locked receiver_locked, ffa_vcpu_index_t vcpu_id,
	ffa_notifications_bitmap_t *from_sp);

/*
 * GET2 variant: supports extended bitmap return and selective retrieval masks.
 * `mask` follows the FF-A v1.3 semantics: bits set are NOT retrieved.
 * mask bit = 0  retrieve; clear pending
 * mask bit = 1  do not retrieve; leave pending
 */
struct ffa_value ffa_notifications_get2_from_sp(
	struct vm_locked receiver_locked, ffa_vcpu_index_t vcpu_id,
	ffa_notifications_bitmap_t mask, ffa_notifications_bitmap_t *from_sp);

struct ffa_value ffa_notifications_get_framework_notifications(
	struct vm_locked receiver_locked, ffa_notifications_bitmap_t *from_fwk,
	ffa_notification_flags_t flags, ffa_vcpu_index_t vcpu_id);

struct ffa_value ffa_notifications_get2_framework_notifications(
	struct vm_locked receiver_locked, ffa_notifications_bitmap_t *from_spm,
	ffa_notifications_bitmap_t *from_hyp,
	ffa_notifications_bitmap_t spm_mask,
	ffa_notifications_bitmap_t hyp_mask, ffa_notification_flags_t flags,
	ffa_vcpu_index_t vcpu_id);

/**
 * Creates a bitmap for the VM of the given ID.
 */
struct ffa_value ffa_notifications_bitmap_create(ffa_id_t vm_id,
						 ffa_vcpu_count_t vcpu_count,
						 uint16_t notification_count);

/**
 * Issues a FFA_NOTIFICATION_BITMAP_CREATE.
 * Returns true if the call goes well, and false if call returns with
 * FFA_ERROR_32.
 */
bool ffa_notifications_bitmap_create_call(
	ffa_id_t vm_id, ffa_vcpu_count_t vcpu_count,
	uint16_t requested_notification_count,
	uint16_t *allocated_notification_count);

/**
 * Destroys the notifications bitmap for the given VM ID.
 */
struct ffa_value ffa_notifications_bitmap_destroy(ffa_id_t vm_id);

/**
 * Helper to send SRI and safely update `ffa_sri_state`, if there has been
 * a call to FFA_NOTIFICATION_SET, and the SRI has been delayed.
 * To be called at a context switch to the NWd.
 */
void ffa_notifications_sri_trigger_if_delayed(struct cpu *cpu);

/**
 * Helper to send SRI and safely update `ffa_sri_state`, if it hasn't been
 * delayed in call to FFA_NOTIFICATION_SET.
 */
void ffa_notifications_sri_trigger_not_delayed(struct cpu *cpu);

/**
 * Track that in current CPU there was a notification set with delay SRI flag.
 */
void ffa_notifications_sri_set_delayed(struct cpu *cpu);

/**
 * Initialize Schedule Receiver Interrupts needed in the context of
 * notifications support.
 */
void ffa_notifications_sri_init(struct cpu *cpu);

void ffa_notifications_info_get_forward(uint16_t *ids, uint32_t *ids_count,
					uint32_t *lists_sizes,
					uint32_t *lists_count,
					uint32_t ids_count_max);
