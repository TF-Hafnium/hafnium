/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include <stdbool.h>

void exception_setup(void (*irq)(void), bool (*exception)(void));
void interrupt_wait(void);
void interrupts_enable(void);
void interrupts_disable(void);
