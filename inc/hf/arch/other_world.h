/*
 * Copyright 2020 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "hf/ffa.h"
#include "hf/vm.h"

struct sve_other_world_context_t {
	uint8_t vectors[32][HF_SVE_VECTOR_LENGTH / 8];

	/* FFR and predicates are one-eigth of the SVE vector length */
	uint8_t ffr[HF_SVE_VECTOR_LENGTH / 64];

	uint8_t predicates[16][HF_SVE_VECTOR_LENGTH / 64];
} __attribute__((aligned(16)));

void arch_other_world_log_init(void);
void arch_other_world_init(void);
bool arch_other_world_vm_init(struct vm *other_world_vm, struct mpool *ppool);
struct ffa_value arch_other_world_call(struct ffa_value args);
bool arch_other_world_is_direct_request_valid(struct vcpu *current,
					      ffa_vm_id_t sender_vm_id,
					      ffa_vm_id_t receiver_vm_id);
bool arch_other_world_is_direct_response_valid(struct vcpu *current,
					       ffa_vm_id_t sender_vm_id,
					       ffa_vm_id_t receiver_vm_id);
