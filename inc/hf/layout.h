/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "hf/addr.h"

#define LINUX_ALIGNMENT 0x200000
#define LINUX_OFFSET 0x80000

paddr_t layout_text_begin(void);
paddr_t layout_text_end(void);

paddr_t layout_rodata_begin(void);
paddr_t layout_rodata_end(void);

paddr_t layout_data_begin(void);
paddr_t layout_data_end(void);

paddr_t layout_stacks_begin(void);
paddr_t layout_stacks_end(void);

paddr_t layout_initrd_begin(void);
paddr_t layout_initrd_end(void);

paddr_t layout_fdt_begin(void);
paddr_t layout_fdt_end(void);

paddr_t layout_image_end(void);

paddr_t layout_primary_begin(void);
