/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "int_state.h"

void hftest_twdog_state_set(enum int_state state);

bool hftest_twdog_state_is(enum int_state to_set);

void hftest_twdog_state_page_setup(void *recv_buf, void *send_buf);

void hftest_twdog_state_share_page_and_init(uint64_t page,
					    ffa_id_t receivers_ids[],
					    size_t receivers_count,
					    void *send_buf);
