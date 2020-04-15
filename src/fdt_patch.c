/*
 * Copyright 2020 The Hafnium Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "hf/fdt_patch.h"

#include <libfdt.h>

#include "hf/boot_params.h"
#include "hf/dlog.h"
#include "hf/fdt.h"
#include "hf/fdt_handler.h"
#include "hf/layout.h"
#include "hf/mm.h"

static bool patch_uint(void *fdt, int off, const char *prop, uint64_t val)
{
	const void *data;
	int lenp;

	data = fdt_getprop(fdt, off, prop, &lenp);
	if (data == NULL) {
		return false;
	}

	switch (lenp) {
	case sizeof(uint64_t): {
		return fdt_setprop_inplace_u64(fdt, off, prop, val) == 0;
	}
	case sizeof(uint32_t): {
		return (val <= UINT32_MAX) &&
		       (fdt_setprop_inplace_u32(fdt, off, prop, val) == 0);
	}
	default: {
		return false;
	}
	}
}

static bool add_mem_reservation(void *fdt, paddr_t begin, paddr_t end)
{
	size_t len = pa_difference(begin, end);

	return fdt_add_mem_rsv(fdt, pa_addr(begin), len) == 0;
}

bool fdt_patch(struct mm_stage1_locked stage1_locked, paddr_t fdt_addr,
	       struct boot_params_update *p, struct mpool *ppool)
{
	void *fdt;
	size_t buf_size;
	int off;
	bool ret = false;
	bool rsv;
	size_t i;

	/* Map the fdt header in. */
	fdt = mm_identity_map(stage1_locked, fdt_addr,
			      pa_add(fdt_addr, FDT_V17_HEADER_SIZE), MM_MODE_R,
			      ppool);
	if (!fdt) {
		dlog_error("Unable to map FDT header.\n");
		return false;
	}

	if (fdt_check_header(fdt) != 0) {
		dlog_error("FDT failed header validation.\n");
		goto err_unmap_fdt_header;
	}

	/* Map the fdt (+ a page) in r/w mode in preparation for updating it. */
	buf_size = fdt_totalsize(fdt) + PAGE_SIZE;
	fdt = mm_identity_map(stage1_locked, fdt_addr,
			      pa_add(fdt_addr, buf_size), MM_MODE_R | MM_MODE_W,
			      ppool);
	if (!fdt) {
		dlog_error("Unable to map FDT in r/w mode.\n");
		goto err_unmap_fdt_header;
	}

	if (fdt_check_full(fdt, buf_size) != 0) {
		dlog_error("FDT failed validation.\n");
		goto out_unmap_fdt;
	}

	/* Allow some extra room for the modifications to the FDT. */
	if (fdt_open_into(fdt, fdt, buf_size) != 0) {
		dlog_error("FDT failed to open_into.\n");
		goto out_unmap_fdt;
	}

	off = fdt_path_offset(fdt, "/chosen");
	if (off < 0) {
		dlog_error("Unable to find FDT '/chosen' node.\n");
		goto out_unmap_fdt;
	}

	/* Patch FDT to point to new ramdisk. */
	if (!patch_uint(fdt, off, FDT_PROP_INITRD_START,
			pa_addr(p->initrd_begin))) {
		dlog_error("Unable to write" FDT_PROP_INITRD_START "\n");
		goto out_unmap_fdt;
	}

	if (!patch_uint(fdt, off, FDT_PROP_INITRD_END,
			pa_addr(p->initrd_end))) {
		dlog_error("Unable to write " FDT_PROP_INITRD_END "\n");
		goto out_unmap_fdt;
	}

	/*
	 * Patch FDT to reserve hypervisor memory so the primary VM doesn't try
	 * to use it.
	 */
	rsv = true;
	rsv &= add_mem_reservation(fdt, layout_text_begin(), layout_text_end());
	rsv &= add_mem_reservation(fdt, layout_rodata_begin(),
				   layout_rodata_end());
	rsv &= add_mem_reservation(fdt, layout_data_begin(), layout_data_end());

	/* Patch FDT to reserve memory for secondary VMs. */
	for (i = 0; i < p->reserved_ranges_count; ++i) {
		struct mem_range range = p->reserved_ranges[i];

		rsv &= add_mem_reservation(fdt, range.begin, range.end);
	}

	if (!rsv) {
		dlog_error("Unable to add memory reservations to FDT.\n");
		goto out_unmap_fdt;
	}

	if (fdt_pack(fdt) != 0) {
		dlog_error("Failed to pack FDT.\n");
		goto out_unmap_fdt;
	}

	ret = true;

out_unmap_fdt:
	/* Unmap FDT. */
	if (!mm_unmap(stage1_locked, fdt_addr,
		      pa_add(fdt_addr, fdt_totalsize(fdt) + PAGE_SIZE),
		      ppool)) {
		dlog_error("Unable to unmap writable FDT.\n");
		return false;
	}
	return ret;

err_unmap_fdt_header:
	mm_unmap(stage1_locked, fdt_addr, pa_add(fdt_addr, FDT_V17_HEADER_SIZE),
		 ppool);
	return false;
}
