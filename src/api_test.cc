/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

/*
 * This order of headers works around a libc++ issue which prevents
 * "atomic" being included before "stdatomic.h".
 */
#include <gmock/gmock.h>

extern "C" {
#include "hf/api.h"
}

namespace
{
using ::testing::Eq;

TEST(api, vm_get_count)
{
	EXPECT_THAT(api_vm_get_count(), Eq(0));
}

} /* namespace */
