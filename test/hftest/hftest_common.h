/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/fdt.h"
#include "hf/memiter.h"

void hftest_json(void);
void hftest_run(struct memiter suite_name, struct memiter test_name,
		const struct fdt *fdt);
void hftest_help(void);
