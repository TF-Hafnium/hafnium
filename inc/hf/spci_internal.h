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

#include "hf/addr.h"
#include "hf/vm.h"

#include "vmapi/hf/spci.h"

#define SPCI_VERSION_MAJOR 0x0
#define SPCI_VERSION_MINOR 0x9

#define SPCI_VERSION_MAJOR_OFFSET 16

struct spci_mem_transitions {
	int orig_from_mode;
	int orig_to_mode;
	int from_mode;
	int to_mode;
};

/* TODO: Add device attributes: GRE, cacheability, shareability. */
static inline uint32_t spci_memory_attrs_to_mode(uint32_t memory_attributes)
{
	uint32_t mode = 0;
	uint32_t attr_value;

	attr_value = spci_get_lend_access_attr(memory_attributes);
	switch (attr_value) {
	case SPCI_LEND_RO_NX:
		mode |= MM_MODE_R;
		break;

	case SPCI_LEND_RO_X:
		mode |= MM_MODE_R | MM_MODE_X;
		break;

	case SPCI_LEND_RW_NX:
		mode |= MM_MODE_R | MM_MODE_W;
		break;

	case SPCI_LEND_RW_X:
		mode |= MM_MODE_R | MM_MODE_W | MM_MODE_X;
		break;

	default:
		break;
	}
	return mode;
}

spci_return_t spci_msg_handle_architected_message(
	struct vm_locked to_locked, struct vm_locked from_locked,
	const struct spci_architected_message_header
		*architected_message_replica,
	struct spci_message *from_msg_replica, struct spci_message *to_msg);

bool spci_msg_check_transition(struct vm *to, struct vm *from,
			       enum spci_memory_share share,
			       int *orig_from_mode, ipaddr_t begin,
			       ipaddr_t end, uint32_t memory_to_attributes,
			       int *from_mode, int *to_mode);
