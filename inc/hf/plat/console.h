/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "hf/mm.h"
#include "hf/mpool.h"

/** Initialises the console hardware. */
void plat_console_init(void);

/** Initialises any memory mappings that the console driver needs. */
void plat_console_mm_init(struct mm_stage1_locked stage1_locked,
			  struct mpool *ppool);

/** Puts a single character on the console. This is a blocking call. */
void plat_console_putchar(char c);

/** Gets a single character from the console. This is a blocking call. */
char plat_console_getchar(void);
