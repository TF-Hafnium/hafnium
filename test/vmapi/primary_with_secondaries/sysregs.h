/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "vmapi/hf/call.h"

#include "../msr.h"
#include "test/hftest.h"

#define TRY_READ(REG) dlog(#REG "=%#lx\n", read_msr(REG))

#define CHECK_READ(REG, VALUE)       \
	do {                         \
		uintreg_t x;         \
		x = read_msr(REG);   \
		EXPECT_EQ(x, VALUE); \
	} while (0)

/*
 * Checks that the register can be updated. The first value is written and read
 * back and then the second value is written and read back. The values must be
 * different so that success means the register value has been changed and
 * updated as expected without relying on the initial value of the register.
 */
#define CHECK_UPDATE(REG, FROM, TO)   \
	do {                          \
		uintreg_t x;          \
		EXPECT_NE(FROM, TO);  \
		write_msr(REG, FROM); \
		x = read_msr(REG);    \
		EXPECT_EQ(x, FROM);   \
		write_msr(REG, TO);   \
		x = read_msr(REG);    \
		EXPECT_EQ(x, TO);     \
	} while (0)
