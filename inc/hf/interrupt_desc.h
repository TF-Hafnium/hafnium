/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include <stdatomic.h>

#include "hf/arch/types.h"

#include "vmapi/hf/ffa.h"

/**
 * Macros for accessing the bitmap tracking interrupts.
 */
/* The number of bits in each element of the interrupt bitfields. */
#define INTERRUPT_REGISTER_BITS 32

struct interrupt_bitmap {
	uint32_t bitmap[HF_NUM_INTIDS / INTERRUPT_REGISTER_BITS];
};

static inline uint32_t interrupt_bitmap_get_value(
	struct interrupt_bitmap *bitmap, uint32_t intid)
{
	uint32_t index = intid / INTERRUPT_REGISTER_BITS;
	uint32_t shift = intid % INTERRUPT_REGISTER_BITS;

	return (bitmap->bitmap[index] >> shift) & 1U;
}

static inline void interrupt_bitmap_set_value(struct interrupt_bitmap *bitmap,
					      uint32_t intid)
{
	uint32_t index = intid / INTERRUPT_REGISTER_BITS;
	uint32_t shift = intid % INTERRUPT_REGISTER_BITS;

	bitmap->bitmap[index] |= 1U << shift;
}

static inline void interrupt_bitmap_clear_value(struct interrupt_bitmap *bitmap,
						uint32_t intid)
{
	uint32_t index = intid / INTERRUPT_REGISTER_BITS;
	uint32_t shift = intid % INTERRUPT_REGISTER_BITS;

	bitmap->bitmap[index] &= ~(1U << shift);
}

/**
 * Legal values to enable or disable an interrupt through the
 * `INT_RECONFIGURE_ENABLE` command using the `HF_INTERRUPT_RECONFIGURE`
 * paravirtualized interface.
 */
#define INT_DISABLE 0
#define INT_ENABLE 1

/**
 * Implementation defined Encodings for various fields:
 *
 * Security_State:
 *	- Secure:	1
 *	- Non-secure:	0
 *
 * Configuration:
 *	- Edge triggered:	0
 *	- Level sensitive:	1
 * Type:
 *	- SPI:	0b10
 *	- PPI:	0b01
 *	- SGI:	0b00
 *
 */
#define INT_DESC_SEC_STATE_NS 0
#define INT_DESC_SEC_STATE_S 1

#define INT_DESC_TYPE_SPI 2
#define INT_DESC_TYPE_PPI 1
#define INT_DESC_TYPE_SGI 0

struct interrupt_descriptor {
	uint32_t interrupt_id;

	uint8_t res : 4;
	uint8_t type : 2;
	uint8_t config : 1;
	uint8_t sec_state : 1;
	uint8_t priority;
	bool valid;
	bool mpidr_valid;
	uint64_t mpidr;
	bool enabled;
};
