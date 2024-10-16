/*
 * Copyright 2022 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/boot_info.h"

#include "hf/assert.h"
#include "hf/dlog.h"
#include "hf/ffa.h"
#include "hf/memiter.h"
#include "hf/std.h"

#include "vmapi/hf/ffa.h"

/**
 * Initializes the ffa_boot_info_header in accordance to the specification.
 */
static void ffa_boot_info_header_init(struct ffa_boot_info_header *header,
				      size_t blob_size)
{
	assert(header != NULL);
	assert(blob_size != 0U);

	header->signature = FFA_BOOT_INFO_SIG;
	header->version = FFA_BOOT_INFO_VERSION;
	header->info_blob_size = blob_size;
	header->desc_size = sizeof(struct ffa_boot_info_desc);
	header->desc_count = 0;
	header->desc_offset =
		(uint32_t)offsetof(struct ffa_boot_info_header, boot_info);
	header->reserved = 0U;
}

static void ffa_boot_info_desc_init(struct ffa_boot_info_desc *info_desc,
				    uint8_t content_format, bool std_type,
				    uint8_t type_id, uint32_t size,
				    uint64_t content)
{
	assert(info_desc != NULL);

	/*
	 * Init name size with 0s, as it is currently unused. Data can be
	 * identified checking the type field.
	 */
	memset_s(info_desc, FFA_BOOT_INFO_NAME_LEN, 0, FFA_BOOT_INFO_NAME_LEN);

	info_desc->type = std_type == true ? FFA_BOOT_INFO_TYPE_STD
					   : FFA_BOOT_INFO_TYPE_IMPDEF;
	info_desc->type <<= FFA_BOOT_INFO_TYPE_SHIFT;
	info_desc->type |= (type_id & FFA_BOOT_INFO_TYPE_ID_MASK);

	info_desc->reserved = 0U;
	info_desc->flags =
		((content_format << FFA_BOOT_INFO_FLAG_CONTENT_FORMAT_SHIFT) &
		 FFA_BOOT_INFO_FLAG_CONTENT_FORMAT_MASK);
	info_desc->size = size;
	info_desc->content = content;
}

/*
 * Write initialization parameter to the boot info descriptor array.
 */
static void boot_info_write_desc(struct ffa_boot_info_header *header,
				 uint8_t content_format, bool std_type,
				 uint8_t type_id, uint32_t size,
				 uint64_t content,
				 const size_t max_info_desc_count)
{
	assert(header != NULL);

	/* Check that writing the data won't surpass the blob memory limit. */
	if (header->desc_count >= max_info_desc_count) {
		dlog_error(
			"Boot info memory is full. No space for a "
			"descriptor.\n");
		return;
	}

	ffa_boot_info_desc_init(&header->boot_info[header->desc_count],
				content_format, std_type, type_id, size,
				content);

	header->desc_count++;
}

/**
 * Looks for the FF-A manifest boot information node, and writes the
 * requested information into the boot info memory.
 */
bool ffa_boot_info_node(struct fdt_node *boot_info_node,
			struct partition_pkg *pkg)
{
	struct memiter data;
	struct ffa_boot_info_header *boot_info_header;
	const size_t boot_info_size =
		pa_difference(pkg->boot_info.begin, pkg->boot_info.end);
	const size_t max_boot_info_desc_count =
		(boot_info_size -
		 offsetof(struct ffa_boot_info_header, boot_info)) /
		sizeof(struct ffa_boot_info_desc);
	bool ret = false;

	assert(boot_info_node != NULL);
	assert(pkg != NULL);

	boot_info_header = (struct ffa_boot_info_header *)ptr_from_va(
		va_from_pa(pkg->boot_info.begin));

	assert(boot_info_header != NULL);

	/*
	 * FF-A v1.1 EAC0 specification states the region for the boot info
	 * descriptors, and the contents of the boot info shall be contiguous.
	 * Together they constitute the boot info blob. The are for the boot
	 * info blob is allocated in the SP's respective package.
	 * Retrieve from the SP package the size of the region for the boot info
	 * descriptors. The size of boot info contents to be incremented,
	 * depending on the info specified in the partition's FF-A manifest.
	 */
	ffa_boot_info_header_init(boot_info_header, boot_info_size);

	if (!fdt_is_compatible(boot_info_node, "arm,ffa-manifest-boot-info")) {
		dlog_verbose("The node 'boot-info' is not compatible.\n");
		return false;
	}

	dlog_verbose("  FF-A Boot Info: base %lx\n",
		     (uintptr_t)ptr_from_va(va_from_pa(pkg->boot_info.begin)));

	if (fdt_read_property(boot_info_node, "ffa_manifest", &data) &&
	    memiter_size(&data) == 0U) {
		ipaddr_t manifest_address = ipa_from_pa(pkg->pm.begin);
		const uint32_t pm_size =
			pa_difference(pkg->pm.begin, pkg->pm.end);

		dlog_verbose("    FF-A Manifest: %lx\n",
			     ipa_addr(manifest_address));
		boot_info_write_desc(boot_info_header,
				     FFA_BOOT_INFO_FLAG_CONTENT_FORMAT_ADDR,
				     true, FFA_BOOT_INFO_TYPE_ID_FDT, pm_size,
				     ipa_addr(manifest_address),
				     max_boot_info_desc_count);

		/*
		 * Incrementing the size of the boot information blob with the
		 * size of the partition's manifest.
		 */
		boot_info_header->info_blob_size += pm_size;

		ret = true;
	}

	if (fdt_read_property(boot_info_node, "hob_list", &data) &&
	    memiter_size(&data) == 0U) {
		ipaddr_t hob_address = ipa_from_pa(pkg->hob.begin);
		const uint32_t hob_size =
			pa_difference(pkg->hob.begin, pkg->hob.end);

		dlog_verbose("    Hob List: %lx, size: %x\n",
			     ipa_addr(hob_address), hob_size);
		boot_info_write_desc(boot_info_header,
				     FFA_BOOT_INFO_FLAG_CONTENT_FORMAT_ADDR,
				     true, FFA_BOOT_INFO_TYPE_ID_HOB, hob_size,
				     ipa_addr(hob_address),
				     max_boot_info_desc_count);

		/*
		 * Incrementing the size of the boot information blob with the
		 * size of the partition's manifest.
		 */
		boot_info_header->info_blob_size += hob_size;

		ret = true;
	}

	if (ret == true) {
		/*
		 * Flush the data cache in case partition initializes with
		 * caches disabled.
		 */
		arch_mm_flush_dcache((void *)boot_info_header,
				     boot_info_header->info_blob_size);
	}

	return ret;
}
