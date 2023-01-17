/*
 * Copyright 2020 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include <stdbool.h>
#include <stdint.h>

#define FW_CFG_ID 0x01
#define FW_CFG_SIGNATURE 0x00
#define FW_CFG_FEATURES 0x01
#define FW_CFG_KERNEL_SIZE 0x08
#define FW_CFG_INITRD_SIZE 0x0b
#define FW_CFG_KERNEL_DATA 0x11
#define FW_CFG_INITRD_DATA 0x12

uint32_t fw_cfg_read_uint32(uint16_t key);
void fw_cfg_read_bytes(uint16_t key, uint8_t *destination, uint32_t length);
bool fw_cfg_read_dma(uint16_t key, uintptr_t destination, uint32_t length);
