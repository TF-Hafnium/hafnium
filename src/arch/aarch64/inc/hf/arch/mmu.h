/*
 * Copyright 2020 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

/** AArch64-specific mapping modes */

/** Mapping mode defining MMU Stage-1 block/page non-secure bit */
#define MM_MODE_NS UINT32_C(0x0080)
