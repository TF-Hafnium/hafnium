/*
 * Copyright 2026 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/check.h"
#include "hf/dlog.h"
#include "hf/ffa/notifications.h"

bool ffa_notifications_bitmap_create_process_response(
	ffa_id_t vm_id, uint16_t requested_notification_count,
	struct ffa_value response, uint16_t *allocated_notification_count)
{
	uint32_t encoded_notification_count;

	CHECK(allocated_notification_count != NULL);
	CHECK(requested_notification_count >= FFA_NOTIFICATION_COUNT_BASE);
	CHECK(requested_notification_count <= MAX_FFA_NOTIFICATIONS);

	if (response.func == FFA_ERROR_32) {
		dlog_error(
			"Failed to create notifications bitmap "
			"to VM: %#x; error: %#x.\n",
			vm_id, ffa_error_code(response));
		return false;
	}

	/*
	 * FFA_NOTIFICATION_BITMAP_CREATE returns the allocated SP
	 * notification count in w2[8:0]. The encoded value represents the
	 * number of notification IDs above the legacy base of 64.
	 */
	encoded_notification_count =
		(uint32_t)response.arg2 & FFA_NOTIFICATION_COUNT_MASK;

	/* Reject an allocation above Hafnium's maximum count of 384. */
	if (encoded_notification_count >
	    FFA_NOTIFICATION_COUNT_ENCODE(MAX_FFA_NOTIFICATIONS)) {
		dlog_error(
			"SPMC returned an invalid notification count: %#x.\n",
			encoded_notification_count);
		return false;
	}

	*allocated_notification_count =
		FFA_NOTIFICATION_COUNT_DECODE(encoded_notification_count);

	/*
	 * The SPMC may allocate more notification IDs than requested, but it
	 * must not allocate fewer.
	 */
	if (*allocated_notification_count < requested_notification_count) {
		dlog_error(
			"SPMC allocated fewer notifications than requested: "
			"%u < %u.\n",
			*allocated_notification_count,
			requested_notification_count);
		return false;
	}

	return true;
}
