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
	struct ffa_boot_info_header* boot_info_header = get_boot_info_header();
	struct ffa_boot_info_desc* fdt_info =
		get_boot_info_desc(boot_info_header, FFA_BOOT_INFO_TYPE_STD,
				   FFA_BOOT_INFO_TYPE_ID_FDT);

	(void)is_boot_vcpu;

	// NOLINTNEXTLINE(performance-no-int-to-ptr)
	hftest_service_main((void*)fdt_info->content);
}
