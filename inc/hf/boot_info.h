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
#include "hf/partition_pkg.h"

#define FFA_BOOT_INFO_SIG 0xFFAU

bool ffa_boot_info_node(struct fdt_node *boot_info_node,
			struct partition_pkg *pkg,
			enum ffa_version vm_ffa_version);
