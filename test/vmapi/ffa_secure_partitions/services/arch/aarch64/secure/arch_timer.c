/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/vm/timer.h"

#include "vmapi/hf/call.h"

#include "partition_services.h"
#include "sp_helpers.h"
#include "test/hftest.h"
#include "test/vmapi/ffa.h"

#define LAST_SP_ID 0x8003

/* Periodic timer expiry. */
uint32_t periodic_timer_ms = 10000;

struct ffa_value sp_program_arch_timer_sleep_cmd(ffa_id_t source,
						 uint32_t timer_delay_ms,
						 uint32_t sleep_ms,
						 uint32_t fwd)
{
	uint64_t time_lapsed;
	ffa_id_t own_id = hf_vm_get_id();
	struct ffa_value fwd_ret;

	HFTEST_LOG("SP%x Request to fire timer after %ums and sleep %ums",
		   own_id, timer_delay_ms, sleep_ms);

	periodic_timer_ms = timer_delay_ms;
	timer_set(timer_delay_ms);
	timer_start();

	time_lapsed = sp_sleep_active_wait(sleep_ms);

	HFTEST_LOG("Sleep complete: %lu", time_lapsed);

	if (fwd != 0 && own_id != LAST_SP_ID) {
		ffa_id_t fwd_target = own_id + 1;

		fwd_ret = sp_program_arch_timer_sleep_cmd_send(
			own_id, fwd_target, timer_delay_ms, sleep_ms, fwd);

		if (fwd_ret.func == FFA_ERROR_32) {
			return sp_error(own_id, source, 0);
		}
	}

	return sp_success(own_id, source, time_lapsed);
}
