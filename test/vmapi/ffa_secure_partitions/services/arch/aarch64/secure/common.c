/*
 * Copyright 2021 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/barriers.h"
#include "hf/arch/vm/timer.h"

#include "hf/dlog.h"

#include "vmapi/hf/call.h"

#include "partition_services.h"
#include "test/vmapi/ffa.h"

struct ffa_value sp_check_ffa_return_resp(ffa_id_t test_source, ffa_id_t own_id,
					  struct ffa_value res)
{
	if (res.func == FFA_ERROR_32) {
		dlog_error("FF-A error returned %x\n", ffa_error_code(res));
		return sp_error(own_id, test_source, ffa_error_code(res));
	}

	return sp_success(own_id, test_source, 0);
}

ffa_id_t sp_find_next_endpoint(ffa_id_t self_id)
{
	if (self_id == SP_ID(3)) {
		return SP_ID(1);
	}

	return (self_id + 1);
}

static inline uint64_t physicalcounter_read(void)
{
	isb();
	return read_msr(cntpct_el0);
}

uint64_t sp_sleep_active_wait(uint32_t ms)
{
	uint64_t timer_freq = read_msr(cntfrq_el0);

	uint64_t time1 = physicalcounter_read();
	volatile uint64_t time2 = time1;

	while ((time2 - time1) < ((ms * timer_freq) / 1000U)) {
		time2 = physicalcounter_read();
	}

	return ((time2 - time1) * 1000) / timer_freq;
}
