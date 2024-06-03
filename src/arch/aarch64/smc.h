/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include <stdint.h>

#include "vmapi/hf/ffa.h"

/* clang-format off */

#define SMCCC_CALL_TYPE_MASK  0x80000000
#define SMCCC_YIELDING_CALL   0x00000000
#define SMCCC_FAST_CALL       0x80000000

#define SMCCC_CONVENTION_MASK 0x40000000
#define SMCCC_32_BIT          0x00000000
#define SMCCC_64_BIT          0x40000000
#define SMCCC_SVE_HINT_MASK   0x00010000

#define SMCCC_SERVICE_CALL_MASK                0x3f000000
#define SMCCC_ARM_ARCHITECTURE_CALL            0x00000000
#define SMCCC_CPU_SERVICE_CALL                 0x01000000
#define SMCCC_SIP_SERVICE_CALL                 0x02000000
#define SMCCC_OEM_SERVICE_CALL                 0x03000000
#define SMCCC_STANDARD_SECURE_SERVICE_CALL     0x04000000
#define SMCCC_STANDARD_HYPERVISOR_SERVICE_CALL 0x05000000
#define SMCCC_VENDOR_HYPERVISOR_SERVICE_CALL   0x06000000

#define SMCCC_CALLER_HYPERVISOR   0x0

/* SMCCC return codes. */
#define SMCCC_OK 0

/* NOT defined by the SMCCC */
#define SMCCC_DENIED (-3)
#define SMCCC_INVALID (-4)

/*
 * TODO: Trusted application call: 0x30000000 - 0x31000000
 * TODO: Trusted OS call: 0x32000000 - 0x3f000000
 */

#define SMCCC_ERROR_UNKNOWN (-1)

#define SMCCC_VERSION_FUNC_ID	0x80000000
#define SMCCC_VERSION_1_2	0x10002

/* clang-format on */

struct ffa_value smc32(uint32_t func, uint32_t arg0, uint32_t arg1,
		       uint32_t arg2, uint32_t arg3, uint32_t arg4,
		       uint32_t arg5, uint32_t caller_id);

struct ffa_value smc64(uint32_t func, uint64_t arg0, uint64_t arg1,
		       uint64_t arg2, uint64_t arg3, uint64_t arg4,
		       uint64_t arg5, uint32_t caller_id);

struct ffa_value smc_forward(uint32_t func, uint64_t arg0, uint64_t arg1,
			     uint64_t arg2, uint64_t arg3, uint64_t arg4,
			     uint64_t arg5, uint32_t caller_id);

struct ffa_value smc_ffa_call(struct ffa_value args);
struct ffa_value smc_ffa_call_ext(struct ffa_value args);
