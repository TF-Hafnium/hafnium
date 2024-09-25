/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "hf/arch/types.h"

#include "hf/vcpu.h"

void host_timer_disable(void);
void host_timer_init(void);
void host_timer_save_arch_timer(struct timer_state *timer);
void host_timer_track_deadline(struct timer_state *timer);
