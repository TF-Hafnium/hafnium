/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include <stddef.h>

#define SERVICE_VM1 (HF_VM_ID_OFFSET + 1)
#define SERVICE_VM2 (HF_VM_ID_OFFSET + 2)
#define SERVICE_VM3 (HF_VM_ID_OFFSET + 3)

#define SELF_INTERRUPT_ID 5
#define EXTERNAL_INTERRUPT_ID_A 7
#define EXTERNAL_INTERRUPT_ID_B 8
#define EXTERNAL_INTERRUPT_ID_C 9

void reverse(char *s, size_t len);
