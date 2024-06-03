/*
 * Copyright 2020 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include <stdint.h>

#include "hf/arch/other_world.h"

#include "hf/addr.h"
#include "hf/ffa.h"
#include "hf/types.h"

#include "smc.h"
#include "test/hftest.h"

alignas(FFA_PAGE_SIZE) static uint8_t tee_send_buffer[HF_MAILBOX_SIZE];
alignas(FFA_PAGE_SIZE) static uint8_t tee_recv_buffer[HF_MAILBOX_SIZE];

/**
 * Make sure FFA_RXTX_MAP to EL3 works.
 */
TEST(arch_tee, init)
{
	struct ffa_value ret = arch_other_world_call((struct ffa_value){
		.func = FFA_RXTX_MAP_64,
		.arg1 = pa_addr(pa_from_va(va_from_ptr(tee_recv_buffer))),
		.arg2 = pa_addr(pa_from_va(va_from_ptr(tee_send_buffer))),
		.arg3 = HF_MAILBOX_SIZE / FFA_PAGE_SIZE});
	uint32_t func = ret.func & ~SMCCC_CONVENTION_MASK;

	/*
	 * TODO(qwandor): Remove this UNKNOWN check once we have a build of TF-A
	 * which supports FF-A memory sharing.
	 */
	if ((int64_t)ret.func != SMCCC_ERROR_UNKNOWN) {
		ASSERT_EQ(func, FFA_SUCCESS_32);
	}
}
