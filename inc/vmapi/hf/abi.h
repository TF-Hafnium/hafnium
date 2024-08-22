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
#define HF_INTERRUPT_ENABLE            0xff03
#define HF_INTERRUPT_GET               0xff04
#define HF_INTERRUPT_DEACTIVATE	       0xff08
#define HF_INTERRUPT_RECONFIGURE       0xff09
#define HF_INTERRUPT_SEND_IPI	       0xff0a

/* Custom FF-A-like calls returned from FFA_RUN. */
#define HF_FFA_RUN_WAIT_FOR_INTERRUPT 0xff06

/* Possible commands that reconfigure an interrupt. */
#define INT_RECONFIGURE_TARGET_PE 0
#define INT_RECONFIGURE_SEC_STATE 1
#define INT_RECONFIGURE_ENABLE 2

/* clang-format on */
