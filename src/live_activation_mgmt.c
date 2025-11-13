/*
 * Copyright 2025 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include <hf/live_activation_helper.h>

static struct spinlock live_activation_tracker_lock_instance = SPINLOCK_INIT;
static struct live_activation_tracker tracker;

struct live_activation_tracker_locked live_activation_tracker_lock(void)
{
	sl_lock(&live_activation_tracker_lock_instance);

	return (struct live_activation_tracker_locked){.tracker = &tracker};
}

void live_activation_tracker_unlocked(
	struct live_activation_tracker_locked *tracker_locked)
{
	assert(tracker_locked->tracker != NULL);
	tracker_locked->tracker = NULL;
	sl_unlock(&live_activation_tracker_lock_instance);
}

void live_activation_tracker_reset(
	struct live_activation_tracker_locked *tracker_locked)
{
	assert(tracker_locked->tracker != NULL);

	/* Initialize various fields of live activation tracker. */
	tracker_locked->tracker->in_progress = false;
	tracker_locked->tracker->partition_id = 0U;
	tracker_locked->tracker->initiator_id = 0U;
}

void live_activation_init(void)
{
	struct live_activation_tracker_locked tracker_locked;

	tracker_locked = live_activation_tracker_lock();

	live_activation_tracker_reset(&tracker_locked);

	live_activation_tracker_unlocked(&tracker_locked);
	dlog_notice("Live activation tracker initialized\n");
}
