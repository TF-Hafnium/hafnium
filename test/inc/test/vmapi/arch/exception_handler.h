/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "vmapi/hf/ffa.h"

ffa_vcpu_index_t get_current_vcpu_index(void);

void exception_handler_set_return_addr(uint64_t instr_addr);

bool exception_handler_skip_instruction(void);

bool exception_handler_skip_to_instruction(void);

bool exception_handler_yield_unknown(void);

bool exception_handler_yield_data_abort(void);

bool exception_handler_yield_instruction_abort(void);

int exception_handler_get_num(void);

void exception_handler_reset(void);

void exception_handler_send_exception_count(void);

int exception_handler_receive_exception_count(const void *recv_buf);

void exception_handler_set_last_interrupt(uint32_t int_id);

uint32_t exception_handler_get_last_interrupt(void);
