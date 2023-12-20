/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/types.h"

#include "hf/vcpu.h"

/** Max SVE vector length supported by the architecture. */
#define HF_SVE_VECTOR_LEN_MAX UINT32_C(2048)

struct sve_context {
	/* FFR and predicates are one-eigth of the SVE vector length */
	uint8_t ffr[HF_SVE_VECTOR_LEN_MAX / 64];

	uint8_t predicates[16][HF_SVE_VECTOR_LEN_MAX / 64];

	uint8_t vectors[32][HF_SVE_VECTOR_LEN_MAX / 8];
} __attribute__((aligned(16)));

void arch_sve_disable_traps(void);
void arch_sve_enable_traps(void);
void arch_sve_configure_vector_length(void);
