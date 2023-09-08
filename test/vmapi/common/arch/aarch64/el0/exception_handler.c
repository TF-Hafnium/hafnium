/*
 * Copyright 2023 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "vmapi/hf/call.h"

/**
 * Tracks the virtual interrupt that was last handled by SP.
 */
static uint32_t last_serviced_interrupt = 0;

/**
 * Updates the last serviced virtual interrupt ID.
 */
void exception_handler_set_last_interrupt(uint32_t id)
{
	last_serviced_interrupt = id;
}

/**
 * Returns the last serviced virtual interrupt ID.
 */
uint32_t exception_handler_get_last_interrupt(void)
{
	return last_serviced_interrupt;
}
