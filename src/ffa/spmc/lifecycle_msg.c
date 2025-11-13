/*
 * Copyright 2025 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/ffa/lifecycle_msg.h"

#include "hf/api.h"
#include "hf/boot_info.h"
#include "hf/call.h"
#include "hf/ffa/interrupts.h"
#include "hf/ffa_internal.h"
#include "hf/live_activation_helper.h"
#include "hf/manifest.h"
#include "hf/partition_pkg.h"
#include "hf/std.h"

struct ffa_value lifecycle_msg_activation_start_req(struct ffa_value args,
						    struct vcpu **next)
{
	(void)args;
	(void)next;

	return api_ffa_interrupt_return(0);
}

struct ffa_value lifecycle_msg_activation_finish_req(struct ffa_value args,
						     struct vcpu **next)
{
	(void)args;
	(void)next;

	return api_ffa_interrupt_return(0);
}

struct ffa_value lifecycle_msg_partition_stop_resp(
	struct ffa_value args, struct vcpu_locked current_locked,
	struct vcpu **next)
{
	(void)args;
	(void)current_locked;
	(void)next;

	return api_ffa_interrupt_return(0);
}
