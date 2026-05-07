/*
 * Copyright 2025 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "hf/vcpu.h"
#include "hf/vm.h"

/*
 * Response code to indicate successful handling of partition live activation
 * start/finish request.
 */
#define LFA_RESPONSE_SUCCESS 0ULL

struct ffa_value lifecycle_msg_activation_start_req(struct ffa_value args,
						    struct vcpu **next);

struct ffa_value lifecycle_msg_activation_finish_req(struct ffa_value args,
						     struct vcpu **next);

struct ffa_value lifecycle_msg_partition_stop_resp(
	struct ffa_value args, struct vcpu_locked current_locked,
	struct vcpu **next);

void lifecycle_sp_activation_complete(struct vcpu_locked current_locked,
				      struct vcpu **next);
