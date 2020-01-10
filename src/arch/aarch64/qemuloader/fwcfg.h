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

#include <stdbool.h>
#include <stdint.h>

#define FW_CFG_ID 0x01
#define FW_CFG_KERNEL_SIZE 0x08
#define FW_CFG_INITRD_SIZE 0x0b
#define FW_CFG_KERNEL_DATA 0x11
#define FW_CFG_INITRD_DATA 0x12

uint32_t fw_cfg_read_uint32(uint16_t key);
void fw_cfg_read_bytes(uint16_t key, uintptr_t destination, uint32_t length);
bool fw_cfg_read_dma(uint16_t key, uintptr_t destination, uint32_t length);
