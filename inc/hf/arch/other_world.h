/*
 * Copyright 2020 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "hf/boot_params.h"
#include "hf/ffa.h"
#include "hf/vm.h"

bool arch_other_world_vm_init(struct vm *other_world_vm,
			      const struct boot_params *params,
			      struct mpool *ppool);
struct ffa_value arch_other_world_call(struct ffa_value args);
struct ffa_value arch_other_world_call_ext(struct ffa_value args);

struct ffa_value arch_other_world_vm_configure_rxtx_map(
	struct vm_locked vm_locked, struct mpool *local_page_pool,
	paddr_t pa_send_begin, paddr_t pa_send_end, paddr_t pa_recv_begin,
	paddr_t pa_recv_end);

struct ffa_value arch_other_world_vm_configure_rxtx_unmap(
	struct vm_locked vm_locked, struct mpool *local_page_pool,
	paddr_t pa_send_begin, paddr_t pa_send_end, paddr_t pa_recv_begin,
	paddr_t pa_recv_end);
