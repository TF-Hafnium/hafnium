/*
 * Copyright 2020 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/tee.h"

#include "hf/check.h"
#include "hf/dlog.h"
#include "hf/ffa.h"
#include "hf/panic.h"
#include "hf/vm.h"

#include "smc.h"

void arch_tee_init(void)
{
	struct vm *tee_vm = vm_find(HF_TEE_VM_ID);
	struct ffa_value ret;
	uint32_t func;

	CHECK(tee_vm != NULL);
	/*
	 * Note that send and recv are swapped around, as the send buffer from
	 * Hafnium's perspective is the recv buffer from the EL3 dispatcher's
	 * perspective and vice-versa.
	 */
	dlog_verbose("Setting up buffers for TEE.\n");
	ret = arch_tee_call((struct ffa_value){
		.func = FFA_RXTX_MAP_64,
		.arg1 = pa_addr(pa_from_va(va_from_ptr(tee_vm->mailbox.recv))),
		.arg2 = pa_addr(pa_from_va(va_from_ptr(tee_vm->mailbox.send))),
		.arg3 = HF_MAILBOX_SIZE / FFA_PAGE_SIZE});
	func = ret.func & ~SMCCC_CONVENTION_MASK;
	if (ret.func == SMCCC_ERROR_UNKNOWN) {
		dlog_error(
			"Unknown function setting up TEE message buffers. "
			"Memory sharing with TEE will not work.\n");
		return;
	}
	if (func == FFA_ERROR_32) {
		panic("Error %d setting up TEE message buffers.", ret.arg2);
	} else if (func != FFA_SUCCESS_32) {
		panic("Unexpected function %#x returned setting up TEE message "
		      "buffers.",
		      ret.func);
	}
	dlog_verbose("TEE finished setting up buffers.\n");
}

struct ffa_value arch_tee_call(struct ffa_value args)
{
	return smc_ffa_call(args);
}
