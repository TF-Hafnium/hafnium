/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include <stdint.h>

#include "hf/check.h"

#include "vmapi/hf/ffa.h"

#define FFA_VERSION_RESERVED_BIT (UINT32_C(1) << 31)

static inline struct ffa_value ffa_error(int32_t error_code)
{
	return (struct ffa_value){.func = FFA_ERROR_32,
				  .arg2 = (uint32_t)error_code};
}

struct ffa_value ffa_msg_recv_return(const struct vm *receiver);

bool is_ffa_direct_msg_request_ongoing(struct vcpu_locked locked);
