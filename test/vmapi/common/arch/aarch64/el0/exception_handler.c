/*
 * Copyright 2023 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "test/vmapi/arch/exception_handler.h"

#include "vmapi/hf/call.h"

/**
 * Get the index of the current vCPU.
 */
ffa_vcpu_index_t get_current_vcpu_index(void)
{
	/*
	 * S-EL0 partitions are required by the FF-A specification to be UP
	 * endpoints.
	 */
	return 0;
}

/**
 * Tracks the virtual interrupt that was last handled by SP.
 */
static uint32_t last_serviced_interrupt = HF_INVALID_INTID;

/**
 * Updates the last serviced virtual interrupt ID.
 */
void exception_handler_set_last_interrupt(uint32_t int_id)
{
	last_serviced_interrupt = int_id;
}

/**
 * Returns the last serviced virtual interrupt ID.
 */
uint32_t exception_handler_get_last_interrupt(void)
{
	return last_serviced_interrupt;
}
