/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include <stdint.h>
#include <stdnoreturn.h>

#include "hf/panic.h"

#include "plat/prng/prng.h"

/**
 * This is the value that is used as the stack canary. It is written to the top
 * of the stack when entering a function and compared against the stack when
 * exiting a function. If there is a mismatch, a failure is triggered.
 *
 * As the value must be the same at the beginning and end of the function, this
 * is a global variable and there are multiple CPUs executing concurrently, this
 * value cannot change after being initialized.
 */
uint64_t __attribute__((used)) __stack_chk_guard = 0x72afaf72bad0feed;

/**
 * Called when the stack canary is invalid. The stack can no longer be trusted
 * so this function must not return.
 */
noreturn void __stack_chk_fail(void)
{
	panic("stack corruption");
}

void __attribute__((no_stack_protector)) stack_protector_init(void)
{
	/* The prng function is executed with the hardcoded stack guard. */
	__stack_chk_guard = (uint64_t)plat_prng_get_number();
}
