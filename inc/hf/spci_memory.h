/*
 * Copyright 2020 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "hf/mpool.h"
#include "hf/vm.h"

#include "vmapi/hf/spci.h"

struct spci_value spci_memory_send(struct vm_locked to_locked,
				   struct vm_locked from_locked,
				   struct spci_memory_region *memory_region,
				   uint32_t memory_share_size,
				   uint32_t share_func,
				   struct mpool *page_pool);
