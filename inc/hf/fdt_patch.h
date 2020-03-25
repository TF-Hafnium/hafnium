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

#pragma once

#include "hf/boot_params.h"
#include "hf/mm.h"
#include "hf/mpool.h"

/** Apply an update to the FDT. */
bool fdt_patch(struct mm_stage1_locked stage1_locked, paddr_t fdt_addr,
	       struct boot_params_update *p, struct mpool *ppool);
