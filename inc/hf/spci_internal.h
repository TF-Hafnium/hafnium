/*
 * Copyright 2019 The Hafnium Authors.
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

#include <stdint.h>

#include "vmapi/hf/spci.h"

#define SPCI_VERSION_MAJOR 0x0
#define SPCI_VERSION_MINOR 0x9

#define SPCI_VERSION_MAJOR_OFFSET 16

typedef uint32_t handle_t;

struct hv_buffers_t {
	uint8_t *rx;
	uint8_t *tx;
};

static inline struct spci_value spci_error(uint64_t error_code)
{
	return (struct spci_value){.func = SPCI_ERROR_32, .arg2 = error_code};
}
