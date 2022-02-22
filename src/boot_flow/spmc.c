/*
 * Copyright 2020 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/plat/boot_flow.h"
#include "hf/std.h"

/* Set by arch-specific boot-time hook. */
uintreg_t plat_boot_flow_fdt_addr;

/**
 * Returns the physical address of SPMC manifest FDT blob. This was passed to
 * SPMC cold boot entry by the SPMD.
 */
paddr_t plat_boot_flow_get_fdt_addr(void)
{
	return pa_init((uintpaddr_t)plat_boot_flow_fdt_addr);
}

/**
 * The value returned by this function is not meaningful in context of the SPMC
 * as there is no primary VM.
 */
uintreg_t plat_boot_flow_get_kernel_arg(void)
{
	return 0;
}

/**
 * The value returned by this function is not meaningful in context of the SPMC
 * as there is no initrd. Initrd begin and end values are cleared such that the
 * check done in one_time_init (initrd_begin is non null) is false, hinting a
 * ramdisk is not present.
 */
bool plat_boot_flow_get_initrd_range(const struct fdt *fdt, paddr_t *begin,
				     paddr_t *end)
{
	(void)fdt;

	*begin = pa_init(0);
	*end = pa_init(0);

	return true;
}

/**
 * This wrapper is unused in context of the SPMC.
 */
bool plat_boot_flow_update(struct mm_stage1_locked stage1_locked,
			   const struct manifest *manifest,
			   struct boot_params_update *update,
			   struct memiter *cpio, struct mpool *ppool)
{
	(void)stage1_locked;
	(void)manifest;
	(void)update;
	(void)cpio;
	(void)ppool;

	return true;
}
