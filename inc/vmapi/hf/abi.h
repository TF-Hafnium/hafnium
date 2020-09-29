/*
 * Copyright 2020 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "hf/spci.h"
#include "hf/types.h"

/* Keep macro alignment */
/* clang-format off */

/* TODO: Define constants below according to spec. */
#define HF_VM_GET_COUNT                0xff01
#define HF_VCPU_GET_COUNT              0xff02
#define HF_MAILBOX_WRITABLE_GET        0xff03
#define HF_MAILBOX_WAITER_GET          0xff04
#define HF_INTERRUPT_ENABLE            0xff05
#define HF_INTERRUPT_GET               0xff06
#define HF_INTERRUPT_INJECT            0xff07

/* Custom SPCI-like calls returned from SPCI_RUN. */
#define HF_SPCI_RUN_WAIT_FOR_INTERRUPT 0xff09
#define HF_SPCI_RUN_WAKE_UP            0xff0a

/* Custom SPCI-like call for relinquishing memory in the push model. */
#define HF_SPCI_MEM_RELINQUISH         0xffab

/* This matches what Trusty and its ATF module currently use. */
#define HF_DEBUG_LOG            0xbd000000

/* clang-format on */
