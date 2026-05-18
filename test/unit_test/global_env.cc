/*
 * Copyright 2026 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

/**
 * This file registers a GoogleTest global environment that initialises
 * the Hafnium memory allocator once for the entire unit test process.
 *
 * The allocator is intentionally initialised only once (before any
 * tests run) so that all the test suites under the unit tests share allocator
 * state. This allows tests to exercise the realistic allocator lifetime
 * behaviour and helps surface leaks or incorrect cleanup that would be
 * hidden by per-test reinitialisation.
 */

#include <gtest/gtest.h> /* GoogleTest APIs (Environment, AddGlobalTestEnvironment) */

extern "C" {
#include "hf/plat/memory_alloc.h"
}

namespace
{
/* Global GoogleTest environment used to initialise the allocator once */
class GlobalAllocatorEnv : public ::testing::Environment
{
       public:
	/* Called once before any unit tests run */
	void SetUp() override
	{
		/* Initialise memory allocator for the unit test process */
		memory_alloc_init();
	}
};

} /* namespace */

/*
 * Register a GoogleTest global environment.
 *
 * AddGlobalTestEnvironment() registers the environment with the GoogleTest
 * framework and transfers ownership to gtest. The environment’s SetUp()
 * method is invoked exactly once before any tests are executed.
 */
static ::testing::Environment *const g_allocator_env =
	::testing::AddGlobalTestEnvironment(new GlobalAllocatorEnv());
