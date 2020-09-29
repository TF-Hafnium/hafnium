/*
 * Copyright 2020 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

/**
 * Performs arch specific boot time initialization.
 *
 * It must only be called once, on first boot and must be called as early as
 * possible.
 */
void arch_one_time_init(void);
