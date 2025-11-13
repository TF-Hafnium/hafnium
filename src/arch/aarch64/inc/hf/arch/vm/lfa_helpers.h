/*
 * Copyright 2025 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "smc.h"

/* clang-format off */

/* Function identifiers for Live Firmware Activation ABIs. */
#define LFA_VERSION		0xc40002e0
#define LFA_FEATURES		0xc40002e1
#define LFA_GET_INFO		0xc40002e2
#define LFA_GET_INVENTORY	0xc40002e3
#define LFA_PRIME		0xc40002e4
#define LFA_ACTIVATE		0xc40002e5
#define LFA_CANCEL		0xc40002e6

/* The following are return codes for LFA. */
enum lfa_return_code : uint32_t {
	LFA_SUCCESS               = 0,
	LFA_NOT_SUPPORTED         = -1,
	LFA_BUSY                  = -2,
	LFA_AUTH_ERROR            = -3,
	LFA_NO_MEMORY             = -4,
	LFA_CRITICAL_ERROR	  = -5,
	LFA_DEVICE_ERROR	  = -6,
	LFA_WRONG_STATE		  = -7,
	LFA_INVALID_PARAMETERS	  = -8,
	LFA_COMPONENT_WRONG_STATE = -9,
	LFA_INVALID_ADDRESS	  = -10,
	LFA_ACTIVATION_FAILED	  = -11,
};

/* Encoding of various fields in flag field returned by LFA_GET_INVENTORY. */
#define LFA_FLAGS_ACTIVATION_CAPABLE	(UINT32_C(1) << 0)
#define LFA_FLAGS_ACTIVATION_PENDING	(UINT32_C(1) << 1)
#define LFA_FLAGS_MAY_RESET_CPU		(UINT32_C(1) << 2)
#define LFA_FLAGS_CPU_RENDEZVOUS	(UINT32_C(1) << 3)

/* Major and minor versions of the LFA supported. */
#define LFA_MAJOR_VERSION	1
#define LFA_MINOR_VERSION	0

/* clang-format on */

uint64_t lfa_get_version(void);
bool lfa_is_feature_supported(uint32_t func_id);
uint32_t lfa_get_info(void);
struct ffa_value lfa_get_inventory(uint32_t component_id);
struct ffa_value lfa_prime(uint32_t component_id);
enum lfa_return_code lfa_activate(uint32_t component_id, uint32_t flags,
				  uintptr_t entry_point_addr,
				  uint64_t context_id);
enum lfa_return_code lfa_cancel(uint32_t component_id);
