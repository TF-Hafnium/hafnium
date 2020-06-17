/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/layout.h"
#include "hf/plat/boot_flow.h"

/**
 * FDT was compiled into Hafnium. Return physical address of the `.plat.fdt`
 * section of Hafnium image.
 */
paddr_t plat_boot_flow_get_fdt_addr(void)
{
	return layout_fdt_begin();
}

/**
 * Android boot flow does not use kernel arguments. Pass zero.
 */
uintreg_t plat_boot_flow_get_kernel_arg(void)
{
	return 0;
}

/**
 * Return the memory range of the RAM disk. This can be either:
 * (a) the range of the '.plat.initrd' section, if it was compiled into the
 *     Hafnium image (INITRD_ADDR and INITRD_SIZE are zero), or
 * (b) a fixed address range known at build time (INITRD_ADDR and INITRD_SIZE
 *     are not zero).
 */
bool plat_boot_flow_get_initrd_range(const struct fdt *fdt, paddr_t *begin,
				     paddr_t *end)
{
	(void)fdt;

	uintpaddr_t initrd_addr = (uintpaddr_t)(INITRD_ADDR);
	size_t initrd_size = (size_t)(INITRD_SIZE);

	if (initrd_addr == 0 || initrd_size == 0) {
		*begin = layout_initrd_begin();
		*end = layout_initrd_end();
	} else {
		*begin = pa_init(initrd_addr);
		*end = pa_add(*begin, initrd_size);
	}
	return true;
}

/**
 * Android boot flow does not change based on the updates.
 */
bool plat_boot_flow_update(struct mm_stage1_locked stage1_locked,
			   const struct manifest *manifest,
			   struct boot_params_update *p, struct memiter *cpio,
			   struct mpool *ppool)
{
	(void)stage1_locked;
	(void)manifest;
	(void)p;
	(void)cpio;
	(void)ppool;

	return true;
}
