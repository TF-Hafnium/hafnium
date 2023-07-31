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
 * Legal values to change the security state of an interrupt.
 */
#define INT_SEC_STATE_NS 0
#define INT_SEC_STATE_S 1

/**
 * Legal values to enable or disable an interrupt through the
 * `INT_RECONFIGURE_ENABLE` command using the `HF_INTERRUPT_RECONFIGURE`
 * paravirtualized interface.
 */
#define INT_DISABLE 0
#define INT_ENABLE 1

/**
 * Attributes encoding in the manifest:

 * Field		Bit(s)
 * ---------------------------
 * Priority		7:0
 * Security_State	8
 * Config(Edge/Level)	9
 * Type(SPI/PPI/SGI)	11:10
 * Reserved		31:12
 *
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

#define INT_DESC_TYPE_SPI 2
#define INT_DESC_TYPE_PPI 1
#define INT_DESC_TYPE_SGI 0

/** Interrupt Descriptor field masks and shifts. */

#define INT_DESC_PRIORITY_SHIFT 0
#define INT_DESC_SEC_STATE_SHIFT 8
#define INT_DESC_CONFIG_SHIFT 9
#define INT_DESC_TYPE_SHIFT 10

struct interrupt_descriptor {
	uint32_t interrupt_id;

	/**
	 * Bit fields	Position
	 * ---------------------
	 * reserved:	7:4
	 * type:	3:2
	 * config:	1
	 * sec_state:	0
	 */
	uint8_t type_config_sec_state;
	uint8_t priority;
	bool valid;
	bool mpidr_valid;
	uint64_t mpidr;
	bool enabled;
};

/**
 * Helper APIs for accessing interrupt_descriptor member variables.
 */
static inline uint32_t interrupt_desc_get_id(
	struct interrupt_descriptor int_desc)
{
	return int_desc.interrupt_id;
}

static inline uint8_t interrupt_desc_get_sec_state(
	struct interrupt_descriptor int_desc)
{
	return ((int_desc.type_config_sec_state >> 0) & 1U);
}

static inline uint8_t interrupt_desc_get_config(
	struct interrupt_descriptor int_desc)
{
	return ((int_desc.type_config_sec_state >> 1) & 1U);
}

static inline uint8_t interrupt_desc_get_type(
	struct interrupt_descriptor int_desc)
{
	return ((int_desc.type_config_sec_state >> 2) & 3U);
}

static inline uint8_t interrupt_desc_get_priority(
	struct interrupt_descriptor int_desc)
{
	return int_desc.priority;
}

static inline uint64_t interrupt_desc_get_mpidr(
	struct interrupt_descriptor int_desc)
{
	return int_desc.mpidr;
}

static inline bool interrupt_desc_get_mpidr_valid(
	struct interrupt_descriptor int_desc)
{
	return int_desc.mpidr_valid;
}

static inline bool interrupt_desc_get_valid(
	struct interrupt_descriptor int_desc)
{
	return int_desc.valid;
}

static inline void interrupt_desc_set_id(struct interrupt_descriptor *int_desc,
					 uint32_t interrupt_id)
{
	int_desc->interrupt_id = interrupt_id;
}

static inline void interrupt_desc_set_mpidr(
	struct interrupt_descriptor *int_desc, uint64_t mpidr)
{
	int_desc->mpidr_valid = true;
	int_desc->mpidr = mpidr;
}

static inline void interrupt_desc_set_mpidr_invalid(
	struct interrupt_descriptor *int_desc)
{
	int_desc->mpidr_valid = false;
	int_desc->mpidr = 0;
}

static inline void interrupt_desc_set_type_config_sec_state(
	struct interrupt_descriptor *int_desc, uint8_t value)
{
	int_desc->type_config_sec_state = value;
}

static inline void interrupt_desc_set_sec_state(
	struct interrupt_descriptor *int_desc, uint8_t value)
{
	/*
	 * Note that the type_config_sec_state field is 8 bit wide. Modify only
	 * the bit[0] of the type_config_sec_state field as it represents the
	 * security state of the interrupt.
	 */
	int_desc->type_config_sec_state =
		(int_desc->type_config_sec_state & 0xFE) | (value & 0x1);
}

static inline void interrupt_desc_set_priority(
	struct interrupt_descriptor *int_desc, uint8_t priority)
{
	int_desc->priority = priority;
}

static inline void interrupt_desc_set_valid(
	struct interrupt_descriptor *int_desc, bool valid)
{
	int_desc->valid = valid;
}

static inline void interrupt_desc_set_enabled(
	struct interrupt_descriptor *int_desc, bool enable)
{
	int_desc->enabled = enable;
}
