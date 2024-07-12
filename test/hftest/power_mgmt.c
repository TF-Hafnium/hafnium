/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/vm/power_mgmt.h"

#include "hf/arch/mm.h"
#include "hf/arch/types.h"

#include "hf/mm.h"
#include "hf/spinlock.h"

#include "test/hftest.h"

struct cpu_start_state {
	cpu_entry_point *entry;
	uintreg_t arg;
	struct spinlock lock;
};

static noreturn void cpu_entry(uintptr_t arg)
{
	/*
	 * The function prototype must match the entry function so we permit the
	 * int to pointer conversion.
	 */
	// NOLINTNEXTLINE(performance-no-int-to-ptr)
	struct cpu_start_state *s = (struct cpu_start_state *)arg;
	struct cpu_start_state s_copy;

	/*
	 * Initialize memory and enable caching. Must be the first thing we do.
	 */
	hftest_mm_vcpu_init();

	/* Make a copy of the cpu_start_state struct. */
	s_copy = *s;

	/* Inform cpu_start() that the state struct memory can now be freed. */
	sl_unlock(&s->lock);

	/* Call the given entry function with the given argument. */
	s_copy.entry(s_copy.arg);

	/* If the entry function returns, turn off the CPU. */
	arch_cpu_stop();
}

bool hftest_cpu_start(cpu_id_t id, const uint8_t *secondary_ec_stack,
		      cpu_entry_point *entry, uintptr_t arg)
{
	struct cpu_start_state s;
	struct arch_cpu_start_state s_arch;

	/*
	 * Config for arch_cpu_start() which will start a new CPU and
	 * immediately jump to cpu_entry(). This function must guarantee that
	 * the state struct is not be freed until cpu_entry() is called.
	 */
	s_arch.initial_sp = (uintptr_t)secondary_ec_stack;
	s_arch.entry = cpu_entry;
	s_arch.arg = (uintptr_t)&s;

	/*
	 * Flush the `cpu_start_state` struct because the new CPU will be
	 * started without caching enabled and will need the data early on.
	 * Write back is all that is really needed so flushing will definitely
	 * get the job done.
	 */
	arch_mm_flush_dcache(&s_arch, sizeof(s_arch));

	if ((s_arch.initial_sp % STACK_ALIGN) != 0) {
		HFTEST_FAIL(true,
			    "Stack pointer of new vCPU not properly aligned.");
	}

	/*
	 * Config for cpu_entry(). Its job is to initialize memory and call the
	 * provided entry point with the provided argument.
	 */
	s.entry = entry;
	s.arg = arg;
	sl_init(&s.lock);

	/*
	 * Lock the cpu_start_state struct which will be unlocked once
	 * cpu_entry() does not need its content anymore. This simultaneously
	 * protects the arch_cpu_start_state struct which must not be freed
	 * before cpu_entry() is called.
	 */
	sl_lock(&s.lock);

	/* Try to start the given CPU. */
	if (!arch_cpu_start(id, &s_arch)) {
		HFTEST_LOG("Couldn't start cpu %lu", id);
		return false;
	}

	/*
	 * Wait until cpu_entry() unlocks the cpu_start_state lock before
	 * freeing stack memory.
	 */
	sl_lock(&s.lock);
	return true;
}
