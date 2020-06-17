/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "smc.h"

/* clang-format off */

/* The following are PSCI version codes. */
#define PSCI_VERSION_0_2 0x00000002
#define PSCI_VERSION_1_0 0x00010000
#define PSCI_VERSION_1_1 0x00010001

/* The following are function identifiers for PSCI. */
#define PSCI_VERSION                 0x84000000
#define PSCI_CPU_SUSPEND             0x84000001
#define PSCI_CPU_OFF                 0x84000002
#define PSCI_CPU_ON                  0x84000003
#define PSCI_AFFINITY_INFO           0x84000004
#define PSCI_MIGRATE                 0x84000005
#define PSCI_MIGRATE_INFO_TYPE       0x84000006
#define PSCI_MIGRATE_INFO_UP_CPU     0x84000007
#define PSCI_SYSTEM_OFF              0x84000008
#define PSCI_SYSTEM_RESET            0x84000009
#define PSCI_FEATURES                0x8400000a
#define PSCI_CPU_FREEZE              0x8400000b
#define PSCI_CPU_DEFAULT_SUSPEND     0x8400000c
#define PSCI_NODE_HW_STATE           0x8400000d
#define PSCI_SYSTEM_SUSPEND          0x8400000e
#define PSCI_SET_SYSPEND_MODE        0x8400000f
#define PSCI_STAT_RESIDENCY          0x84000010
#define PSCI_STAT_COUNT              0x84000011
#define PSCI_SYSTEM_RESET2           0x84000012
#define PSCI_MEM_PROTECT             0x84000013
#define PSCI_MEM_PROTECT_CHECK_RANGE 0x84000014

/* The following are return codes for PSCI. */
#define PSCI_RETURN_ON_PENDING         2
#define PSCI_RETURN_OFF                1
#define PSCI_RETURN_ON                 0
#define PSCI_RETURN_SUCCESS            0
#define PSCI_ERROR_NOT_SUPPORTED       SMCCC_ERROR_UNKNOWN
#define PSCI_ERROR_INVALID_PARAMETERS  (-2)
#define PSCI_ERROR_DENIED              (-3)
#define PSCI_ERROR_ALREADY_ON          (-4)
#define PSCI_ERROR_ON_PENDING          (-5)
#define PSCI_ERROR_INTERNAL_FAILURE    (-6)
#define PSCI_ERROR_NOT_PRESENT         (-7)
#define PSCI_ERROR_DISABLE             (-8)
#define PSCI_ERROR_INVALID_ADDRESS     (-9)

/* clang-format on */
