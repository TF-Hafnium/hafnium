/*
 * Copyright 2025 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "live_buffer.h"

#include "hf/assert.h"

void live_buffer_init(struct live_buffer *buffer, ffa_id_t sp_id)
{
	assert(buffer != NULL);
	buffer->magic = LIVE_STATE_MAGIC;
	buffer->activation_token = 0U;
	buffer->counter = 0U;
	buffer->partition_id = sp_id;
}

bool live_buffer_is_valid(struct live_buffer *buffer)
{
	return buffer->magic == LIVE_STATE_MAGIC;
}

uint32_t live_buffer_get_counter(struct live_buffer *buffer)
{
	assert(buffer != NULL);
	return buffer->counter;
}

void live_buffer_counter_inc(struct live_buffer *buffer)
{
	assert(buffer != NULL);
	buffer->counter++;
}

uint64_t live_buffer_get_token(struct live_buffer *buffer)
{
	assert(buffer != NULL);
	return buffer->activation_token;
}

void live_buffer_set_token(struct live_buffer *buffer, uint64_t value)
{
	assert(buffer != NULL);
	buffer->activation_token = value;
}

ffa_id_t live_buffer_get_partition_id(struct live_buffer *buffer)
{
	assert(buffer != NULL);
	return buffer->partition_id;
}
