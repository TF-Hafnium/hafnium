/*
 * Copyright 2020 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#if SECURE_WORLD == 1
#define HF_VM_ID_BASE 0x8000
#define HF_OTHER_WORLD_ID HF_HYPERVISOR_VM_ID
#else
#define HF_VM_ID_BASE 0
#define HF_OTHER_WORLD_ID HF_TEE_VM_ID
#endif
