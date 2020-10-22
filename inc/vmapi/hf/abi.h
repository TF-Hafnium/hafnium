/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "hf/ffa.h"
#include "hf/types.h"

/* Keep macro alignment */
/* clang-format off */

/* TODO: Define constants below according to spec. */
#define HF_MAILBOX_WRITABLE_GET        0xff01
#define HF_MAILBOX_WAITER_GET          0xff02
#define HF_INTERRUPT_ENABLE            0xff03
#define HF_INTERRUPT_GET               0xff04
#define HF_INTERRUPT_INJECT            0xff05
#define HF_INTERRUPT_DEACTIVATE	       0xff08

/* Custom FF-A-like calls returned from FFA_RUN. */
#define HF_FFA_RUN_WAIT_FOR_INTERRUPT 0xff06

/* This matches what Trusty and its TF-A module currently use. */
#define HF_DEBUG_LOG            0xbd000000

/* clang-format on */
