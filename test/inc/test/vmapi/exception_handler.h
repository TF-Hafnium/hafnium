/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "vmapi/hf/ffa.h"

bool exception_handler_skip_instruction(void);

bool exception_handler_yield_unknown(void);

bool exception_handler_yield_data_abort(void);

bool exception_handler_yield_instruction_abort(void);

int exception_handler_get_num(void);

void exception_handler_reset(void);

void exception_handler_send_exception_count(void);

int exception_handler_receive_exception_count(
	const struct ffa_memory_region *recv_buf);
