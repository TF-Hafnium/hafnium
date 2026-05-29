/*
 * Copyright 2026 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/plat/core.h"

void plat_one_time_init(void)
{
}

bool plat_mm_init(struct mm_stage1_locked stage1_locked)
{
	(void)stage1_locked;
	return true;
}

bool plat_paravirt_interface_handler(struct ffa_value args, struct vcpu *vcpu,
				     struct vcpu **next)
{
	(void)args;
	(void)vcpu;
	(void)next;
	return false;
}

enum manifest_return_code plat_parse_ffa_manifest(
	struct fdt *fdt, struct manifest_vm *vm,
	const struct boot_params *boot_params)
{
	(void)fdt;
	(void)vm;
	(void)boot_params;
	return MANIFEST_SUCCESS;
}

bool plat_load_ffa_partition(struct mm_stage1_locked stage1_locked,
			     paddr_t mem_begin, paddr_t mem_end,
			     const struct manifest_vm *manifest_vm,
			     struct vm *current_vm)
{
	(void)stage1_locked;
	(void)mem_begin;
	(void)mem_end;
	(void)manifest_vm;
	(void)current_vm;
	return true;
}
