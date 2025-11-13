/*
 * Copyright 2025 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "stdint.h"
#include "test/vmapi/ffa.h"

#define LIVE_STATE_MAGIC 0x4C495645  // 'LIVE' in ASCII

/**
 * A dummy structure, represeting a live state buffer, passed between old and
 * new images of a Secure Partition as part of live activation sequence.
 */
struct live_buffer {
	/*
	 * The current image stores a value in the token which is then compared
	 * to expected value by next image after live activation.
	 */
	uint64_t activation_token;

	/*
	 * A unique value passed around live activation sequence. Helps to
	 * identify if the buffer is valid.
	 */
	uint32_t magic;

	/* The id of the partition undergoing live activation. */
	ffa_id_t partition_id;

	/*
	 * A small counter to keep track of number of times this partition has
	 * been live activated.
	 */
	uint8_t counter;

	uint64_t data;
};

void live_buffer_init(struct live_buffer *buffer, ffa_id_t sp_id);
bool live_buffer_is_valid(struct live_buffer *buffer);
uint32_t live_buffer_get_counter(struct live_buffer *buffer);
void live_buffer_counter_inc(struct live_buffer *buffer);
uint64_t live_buffer_get_token(struct live_buffer *buffer);
void live_buffer_set_token(struct live_buffer *buffer, uint64_t value);
ffa_id_t live_buffer_get_partition_id(struct live_buffer *buffer);
