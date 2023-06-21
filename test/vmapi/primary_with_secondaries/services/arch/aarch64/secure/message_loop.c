/*
 * Copyright 2022 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "vmapi/hf/call.h"
#include "vmapi/hf/ffa.h"

#include "test/hftest.h"
#include "test/vmapi/ffa.h"

noreturn void test_main_sp(bool is_boot_vcpu)
{
	/* Use FF-A v1.1 EAC0 boot protocol to retrieve the FDT. */
	static struct ffa_boot_info_desc* fdt_info;

	/* TODO: Place in a common code path. Currently not possible, because
	 * the NWd partitions are not loaded with a Partition Package, which SPs
	 * are. The memory for the boot information is allocated within the
	 * partition package.
	 */
	if (is_boot_vcpu) {
		struct ffa_boot_info_header* boot_info_header =
			get_boot_info_header();

		fdt_info = get_boot_info_desc(boot_info_header,
					      FFA_BOOT_INFO_TYPE_STD,
					      FFA_BOOT_INFO_TYPE_ID_FDT);
	} else {
		/*
		 * Primary core should have initialized the fdt_info structure.
		 */
		assert(fdt_info != NULL);
	}

	// NOLINTNEXTLINE(performance-no-int-to-ptr)
	hftest_service_main((void*)fdt_info->content);
}
