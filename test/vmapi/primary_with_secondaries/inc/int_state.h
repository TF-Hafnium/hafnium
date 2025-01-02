/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "hf/arch/spinlock.h"

#include "test/vmapi/ffa.h"

/**
 * State machine to aid with testing Hafnium's secure interrupt support. From
 * testing perspective, an interrupt could be classified as either software
 * generated (such as IPI) or hardware generated (such as TWDOG).
 */
enum int_state {
	/* Interrupt hasn't been configured by target vCPU. */
	INIT,
	/*
	 * Interrupt has been configured by the target vCPU. This state is
	 * not applicable for hardware generated interrupts.
	 */
	READY,
	/*
	 * Interrupt has been sent to the target vCPU either by software (i.e.
	 * invocation of an ABI) or by configuring a hardware peripheral.
	 */
	SENT,
	/* Interrupt has been handled/serviced by target vCPU. */
	HANDLED,
};

enum int_category {
	SOFTWARE,
	HARDWARE,
};

/**
 * Interrupt state tracked by various endpoints as part of the test.
 */
struct hftest_int_state {
	enum int_state state;
	struct spinlock lock;
	enum int_category category;
	uint32_t interrupt_count;
};

bool hftest_int_state_is(struct hftest_int_state *track,
			 enum int_state to_check);

void hftest_int_state_set(struct hftest_int_state *track,
			  enum int_state to_set);

void hftest_int_state_init(struct hftest_int_state *track,
			   enum int_category category);

uint32_t hftest_int_state_get_interrupt_count(struct hftest_int_state *track);
void hftest_int_state_reset_interrupt_count(struct hftest_int_state *track);

uint64_t hftest_int_state_page_setup(void *recv_buf, void *send_buf);

void hftest_int_state_page_relinquish(void *send_buf);
