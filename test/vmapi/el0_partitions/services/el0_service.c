/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "test/hftest.h"

noreturn void el0_main(const void *fdt_ptr)
{
	hftest_service_main(fdt_ptr);
}
