/*
 * Copyright 2022 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "hf/fdt.h"
#include "hf/ffa.h"
#include "hf/sp_pkg.h"

#define FFA_BOOT_INFO_SIG 0xFFAU
#define FFA_BOOT_INFO_VERSION 0x10001U

bool ffa_boot_info_node(struct fdt_node *boot_info_node, vaddr_t pkg_address,
			struct sp_pkg_header *pkg_header);
