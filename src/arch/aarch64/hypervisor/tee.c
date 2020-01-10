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

#include "hf/arch/tee.h"

#include "hf/check.h"
#include "hf/dlog.h"
#include "hf/panic.h"
#include "hf/spci.h"
#include "hf/vm.h"

#include "smc.h"

void arch_tee_init(void)
{
	struct vm *tee_vm = vm_find(HF_TEE_VM_ID);
	struct spci_value ret;
	uint32_t func;

	CHECK(tee_vm != NULL);
	/*
	 * Note that send and recv are swapped around, as the send buffer from
	 * Hafnium's perspective is the recv buffer from the EL3 dispatcher's
	 * perspective and vice-versa.
	 */
	dlog_verbose("Setting up buffers for TEE.\n");
	ret = arch_tee_call((struct spci_value){
		.func = SPCI_RXTX_MAP_64,
		.arg1 = pa_addr(pa_from_va(va_from_ptr(tee_vm->mailbox.recv))),
		.arg2 = pa_addr(pa_from_va(va_from_ptr(tee_vm->mailbox.send))),
		.arg3 = HF_MAILBOX_SIZE / SPCI_PAGE_SIZE});
	func = ret.func & ~SMCCC_CONVENTION_MASK;
	if (ret.func == SMCCC_ERROR_UNKNOWN) {
		dlog_error(
			"Unknown function setting up TEE message buffers. "
			"Memory sharing with TEE will not work.\n");
		return;
	}
	if (func == SPCI_ERROR_32) {
		panic("Error %d setting up TEE message buffers.", ret.arg2);
	} else if (func != SPCI_SUCCESS_32) {
		panic("Unexpected function %#x returned setting up TEE message "
		      "buffers.",
		      ret.func);
	}
	dlog_verbose("TEE finished setting up buffers.\n");
}

struct spci_value arch_tee_call(struct spci_value args)
{
	return smc_forward(args.func, args.arg1, args.arg2, args.arg3,
			   args.arg4, args.arg5, args.arg6, args.arg7);
}
