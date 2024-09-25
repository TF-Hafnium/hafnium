/*
 * Copyright 2023 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include <stdint.h>

#include "test/hftest.h"

uint64_t sp_sleep_active_wait(uint32_t ms);
void sp_enable_irq(void);
void sp_disable_irq(void);
struct ffa_value handle_interrupt(struct ffa_value res);
void sp_register_secondary_ep(struct hftest_context *ctx);
