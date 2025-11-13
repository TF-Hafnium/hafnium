/*
 * Copyright 2025 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "hf/vm.h"

struct live_activation_tracker {
	bool in_progress;
	ffa_id_t partition_id;
	ffa_id_t initiator_id;
};

/**
 * Encapsulates the live activation tracker while the corresponding lock is
 * held.
 */
struct live_activation_tracker_locked {
	struct live_activation_tracker *tracker;
};

struct live_activation_tracker_locked live_activation_tracker_lock(void);

void live_activation_tracker_unlocked(
	struct live_activation_tracker_locked *tracker_locked);

void live_activation_tracker_reset(
	struct live_activation_tracker_locked *tracker_locked);

void live_activation_init(void);
