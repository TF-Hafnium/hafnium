/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "hf/vm.h"

bool plat_ffa_is_indirect_msg_supported(struct vm_locked sender_locked,
					struct vm_locked receiver_locked);

bool plat_ffa_msg_send2_forward(ffa_id_t receiver_vm_id, ffa_id_t sender_vm_id,
				struct ffa_value *ret);

/**
 * This FF-A v1.0 FFA_MSG_SEND interface.
 * Implemented for the Hypervisor, but not in the SPMC.
 */
struct ffa_value plat_ffa_msg_send(ffa_id_t sender_vm_id,
				   ffa_id_t receiver_vm_id, uint32_t size,
				   struct vcpu *current, struct vcpu **next);

struct ffa_value plat_ffa_msg_recv(bool block,
				   struct vcpu_locked current_locked,
				   struct vcpu **next);
