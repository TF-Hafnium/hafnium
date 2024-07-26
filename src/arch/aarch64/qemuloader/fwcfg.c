/*
 * Copyright 2020 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "fwcfg.h"

#include <stdbool.h>
#include <stdint.h>

#include "hf/arch/std.h"

#include "hf/io.h"

#define FW_CFG_CONTROL_ERROR htobe32(1 << 0)
#define FW_CFG_CONTROL_READ htobe32(1 << 1)
#define FW_CFG_CONTROL_SKIP htobe32(1 << 2)
#define FW_CFG_CONTROL_SELECT htobe32(1 << 3)
#define FW_CFG_CONTROL_WRITE htobe32(1 << 4)

#define FW_CFG_BASE 0x09020000
#define FW_CFG_DATA8 IO8_C(FW_CFG_BASE + 0)
#define FW_CFG_DATA32 IO32_C(FW_CFG_BASE + 0)
#define FW_CFG_SELECTOR IO16_C(FW_CFG_BASE + 8)
#define FW_CFG_DMA IO64_C(FW_CFG_BASE + 16)

struct fw_cfg_dma_access {
	uint32_t control;
	uint32_t length;
	uint64_t address;
};

uint32_t fw_cfg_read_uint32(uint16_t key)
{
	io_write16(FW_CFG_SELECTOR, htobe16(key));
	return io_read32(FW_CFG_DATA32);
}

void fw_cfg_read_bytes(uint16_t key, uint8_t *destination, uint32_t length)
{
	size_t i;

	io_write16(FW_CFG_SELECTOR, htobe16(key));
	for (i = 0; i < length; ++i) {
		destination[i] = io_read8(FW_CFG_DATA8);
	}
}

bool fw_cfg_read_dma(uint16_t key, uintptr_t destination, uint32_t length)
{
	volatile struct fw_cfg_dma_access access = {
		.control = FW_CFG_CONTROL_READ,
		.length = htobe32(length),
		.address = htobe64(destination),
	};
	uint64_t access_address = (uint64_t)&access;
	uint32_t control;

	io_write16(FW_CFG_SELECTOR, htobe16(key));
	io_write64(FW_CFG_DMA, htobe64(access_address));
	data_sync_barrier();

	do {
		control = access.control;
		if (control == 0) {
			break;
		}
		if ((control & FW_CFG_CONTROL_ERROR) != 0) {
			return true;
		}
		if ((control & FW_CFG_CONTROL_READ) == 0) {
			return true;
		}
	} while (1);

	return false;
}
