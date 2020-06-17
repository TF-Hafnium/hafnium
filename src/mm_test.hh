/*
 * Copyright 2019 The Hafnium Authors.
 *
* Use of this source code is governed by a BSD-style
* license that can be found in the LICENSE file or at
* https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include <span>
#include <vector>

namespace mm_test
{
std::vector<std::span<pte_t, MM_PTE_PER_PAGE>> get_ptable(
	const struct mm_ptable &ptable);

} /* namespace mm_test */
