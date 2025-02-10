/*
 * Copyright 2025 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/ffa.h"
#include "hf/arch/other_world.h"

#include "hf/check.h"
#include "hf/dlog.h"
#include "hf/ffa/setup_and_discovery.h"
#include "hf/vcpu.h"
#include "hf/vm.h"

static bool ffa_tee_enabled = false;

bool plat_ffa_is_tee_enabled(void)
{
	return ffa_tee_enabled;
}

void plat_ffa_set_tee_enabled(bool tee_enabled)
{
	ffa_tee_enabled = tee_enabled;
}

void plat_ffa_log_init(void)
{
	dlog_info("Initializing Hafnium (Hypervisor)\n");
}

void plat_ffa_init(struct mpool *ppool)
{
	struct vm *other_world_vm = vm_find(HF_OTHER_WORLD_ID);
	struct ffa_value ret;
	struct mm_stage1_locked mm_stage1_locked;

	/* This is a segment from TDRAM for the NS memory in the FVP platform.
	 *
	 * TODO: We ought to provide a better way to do this, if porting the
	 * hypervisor to other platforms. One option would be to provide this
	 * via DTS.
	 */
	const uint64_t start = 0x90000000;
	const uint64_t len = 0x60000000;
	const paddr_t send_addr = pa_init(start + len - PAGE_SIZE * 1);
	const paddr_t recv_addr = pa_init(start + len - PAGE_SIZE * 2);

	(void)ppool;

	if (!plat_ffa_is_tee_enabled()) {
		return;
	}

	CHECK(other_world_vm != NULL);

	arch_ffa_init();

	/*
	 * Call FFA_VERSION so the SPMC can store the hypervisor's
	 * version. This may be useful if there is a mismatch of
	 * versions.
	 */
	ret = arch_other_world_call((struct ffa_value){
		.func = FFA_VERSION_32, .arg1 = FFA_VERSION_COMPILED});
	if (ret.func == (uint32_t)FFA_NOT_SUPPORTED) {
		panic("Hypervisor and SPMC versions are not compatible.\n");
	}

	/*
	 * Setup TEE VM RX/TX buffers.
	 * Using the following hard-coded addresses, as they must be within the
	 * NS memory node in the SPMC manifest. From that region we should
	 * exclude the Hypervisor's address space to prevent SPs from using that
	 * memory in memory region nodes, or for the NWd to misuse that memory
	 * in runtime via memory sharing interfaces.
	 */

	// NOLINTNEXTLINE(performance-no-int-to-ptr)
	other_world_vm->mailbox.send = (void *)pa_addr(send_addr);
	// NOLINTNEXTLINE(performance-no-int-to-ptr)
	other_world_vm->mailbox.recv = (void *)pa_addr(recv_addr);

	/*
	 * Note that send and recv are swapped around, as the send buffer from
	 * Hafnium's perspective is the recv buffer from the EL3 dispatcher's
	 * perspective and vice-versa.
	 */
	dlog_verbose("Setting up buffers for TEE.\n");
	ffa_setup_rxtx_map_spmc(
		pa_from_va(va_from_ptr(other_world_vm->mailbox.recv)),
		pa_from_va(va_from_ptr(other_world_vm->mailbox.send)),
		HF_MAILBOX_SIZE / FFA_PAGE_SIZE);

	plat_ffa_set_tee_enabled(true);

	/*
	 * Hypervisor will write to secure world receive buffer, and will read
	 * from the secure world send buffer.
	 *
	 * Mapping operation is necessary because the ranges are outside of the
	 * hypervisor's binary.
	 */
	mm_stage1_locked = mm_lock_stage1();
	CHECK(mm_identity_map(mm_stage1_locked, send_addr,
			      pa_add(send_addr, PAGE_SIZE),
			      MM_MODE_R | MM_MODE_SHARED, ppool) != NULL);
	CHECK(mm_identity_map(
		      mm_stage1_locked, recv_addr, pa_add(recv_addr, PAGE_SIZE),
		      MM_MODE_R | MM_MODE_W | MM_MODE_SHARED, ppool) != NULL);
	mm_unlock_stage1(&mm_stage1_locked);

	dlog_verbose("TEE finished setting up buffers.\n");
}
