/*
 * Copyright 2020 The Hafnium Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "hf/arch/tee.h"

#include <stdint.h>

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
	struct ffa_value ret = arch_tee_call((struct ffa_value){
		.func = FFA_RXTX_MAP_64,
		.arg1 = pa_addr(pa_from_va(va_from_ptr(tee_recv_buffer))),
		.arg2 = pa_addr(pa_from_va(va_from_ptr(tee_send_buffer))),
		.arg3 = HF_MAILBOX_SIZE / FFA_PAGE_SIZE});
	uint32_t func = ret.func & ~SMCCC_CONVENTION_MASK;

	/*
	 * TODO(qwandor): Remove this UNKNOWN check once we have a build of TF-A
	 * which supports FF-A memory sharing.
	 */
	if (ret.func != SMCCC_ERROR_UNKNOWN) {
		ASSERT_EQ(func, FFA_SUCCESS_32);
	}
}
