/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include <gmock/gmock.h>

extern "C" {
#include "hf/arch/mm.h"

#include "hf/check.h"
#include "hf/hf_ipi.h"
#include "hf/mm.h"
}

#include <map>

#include "mm_test.hh"

namespace
{
using namespace ::std::placeholders;
using ::testing::AllOf;
using ::testing::Each;
using ::testing::SizeIs;
using struct_vm = struct vm;
using struct_vcpu = struct vcpu;
using struct_vm_locked = struct vm_locked;

/**
 * IPI Test to check sent IPIs are correctly recorded as pending.
 */

constexpr size_t TEST_HEAP_SIZE = PAGE_SIZE * 64;
const mm_level_t TOP_LEVEL = arch_mm_stage2_max_level();
class ipi : public ::testing::Test
{
       protected:
	static std::unique_ptr<uint8_t[]> test_heap;
	struct mpool ppool;
	struct_vm *test_vm[4];
	void SetUp() override
	{
		if (test_heap) {
			return;
		}
		test_heap = std::make_unique<uint8_t[]>(TEST_HEAP_SIZE);
		mpool_init(&ppool, sizeof(struct mm_page_table));
		mpool_add_chunk(&ppool, test_heap.get(), TEST_HEAP_SIZE);
		for (size_t i = 0; i < std::size(test_vm); i++) {
			test_vm[i] = vm_init(i + HF_VM_ID_OFFSET, MAX_CPUS,
					     &ppool, false, 0);
		}

		for (size_t i = 0; i < MAX_CPUS; i++) {
			struct vcpu *running_vcpu = vm_get_vcpu(test_vm[0], i);
			struct vcpu *waiting_vcpu = vm_get_vcpu(test_vm[1], i);
			struct vcpu *blocked_vcpu = vm_get_vcpu(test_vm[2], i);
			struct vcpu *preempted_vcpu =
				vm_get_vcpu(test_vm[3], i);
			struct vcpu_locked running_locked =
				vcpu_lock(running_vcpu);
			struct vcpu_locked waiting_locked =
				vcpu_lock(waiting_vcpu);
			struct vcpu_locked blocked_locked =
				vcpu_lock(blocked_vcpu);
			struct vcpu_locked preempted_locked =
				vcpu_lock(preempted_vcpu);

			struct cpu *cpu = cpu_find_index(i);

			running_vcpu->cpu = cpu;
			running_vcpu->state = VCPU_STATE_RUNNING;
			vcpu_virt_interrupt_enable(running_locked, HF_IPI_INTID,
						   true);

			waiting_vcpu->cpu = cpu;
			waiting_vcpu->state = VCPU_STATE_WAITING;
			vcpu_virt_interrupt_enable(waiting_locked, HF_IPI_INTID,
						   true);

			blocked_vcpu->cpu = cpu;
			blocked_vcpu->state = VCPU_STATE_BLOCKED;
			vcpu_virt_interrupt_enable(blocked_locked, HF_IPI_INTID,
						   true);

			preempted_vcpu->cpu = cpu;
			preempted_vcpu->state = VCPU_STATE_PREEMPTED;
			vcpu_virt_interrupt_enable(preempted_locked,
						   HF_IPI_INTID, true);

			list_init(&cpu->pending_ipis);

			vcpu_unlock(&running_locked);
			vcpu_unlock(&waiting_locked);
			vcpu_unlock(&blocked_locked);
			vcpu_unlock(&preempted_locked);
		}
	}
};

std::unique_ptr<uint8_t[]> ipi::test_heap;

/**
 * Check that when an IPI is sent to vCPU0, vCPU0 is
 * stored as the pending target_vcpu within the IPI framework.
 *
 * This function also sets the vm at index 1 to running on all
 * CPUs. This is used in later tests.
 */
TEST_F(ipi, one_service_to_one_cpu)
{
	struct_vm *current_vm = ipi::test_vm[0];
	ffa_vcpu_count_t vcpu_count = current_vm->vcpu_count;

	CHECK(vcpu_count == MAX_CPUS);

	for (size_t i = 0; i < MAX_CPUS; i++) {
		struct vcpu *vcpu = vm_get_vcpu(current_vm, i);
		struct cpu *cpu = cpu_find_index(i);
		vcpu->cpu = cpu;
		vcpu->state = VCPU_STATE_RUNNING;
		list_init(&cpu->pending_ipis);
	}

	hf_ipi_send_interrupt(current_vm, 0);

	/* Check vCPU0 is stored as having a pending interrupt on CPU 0. */
	EXPECT_EQ(hf_ipi_get_pending_target_vcpu(vm_get_vcpu(current_vm, 0)),
		  vm_get_vcpu(current_vm, 0));
	/* Check that there are no longer pending interrupts on CPU 0. */
	EXPECT_EQ(hf_ipi_get_pending_target_vcpu(vm_get_vcpu(current_vm, 0)),
		  (struct vcpu *)NULL);
}

/**
 * Check if one service sends IPIs to different target vCPUs they are stored
 * under the correct CPUs.
 */
TEST_F(ipi, one_service_to_different_cpus)
{
	struct_vm *current_vm = ipi::test_vm[0];
	ffa_vcpu_count_t vcpu_count = current_vm->vcpu_count;

	CHECK(vcpu_count >= 2);

	hf_ipi_send_interrupt(current_vm, 0);
	hf_ipi_send_interrupt(current_vm, 1);

	EXPECT_EQ(hf_ipi_get_pending_target_vcpu(vm_get_vcpu(current_vm, 0)),
		  vm_get_vcpu(current_vm, 0));
	EXPECT_EQ(hf_ipi_get_pending_target_vcpu(vm_get_vcpu(current_vm, 1)),
		  vm_get_vcpu(current_vm, 1));
}

/**
 * Multiple services targeting IPIs to CPU0,1,2 and 3 respectively.
 */
TEST_F(ipi, multiple_services_to_different_cpus)
{
	struct_vm *running_vm = ipi::test_vm[0];
	struct_vm *waiting_vm = ipi::test_vm[1];
	struct_vm *blocked_vm = ipi::test_vm[2];
	struct_vm *preempted_vm = ipi::test_vm[3];

	hf_ipi_send_interrupt(running_vm, 0);
	hf_ipi_send_interrupt(waiting_vm, 1);
	hf_ipi_send_interrupt(blocked_vm, 2);
	hf_ipi_send_interrupt(preempted_vm, 3);

	EXPECT_EQ(hf_ipi_get_pending_target_vcpu(vm_get_vcpu(running_vm, 0)),
		  vm_get_vcpu(running_vm, 0));
	EXPECT_EQ(hf_ipi_get_pending_target_vcpu(vm_get_vcpu(running_vm, 1)),
		  vm_get_vcpu(waiting_vm, 1));
	EXPECT_EQ(hf_ipi_get_pending_target_vcpu(vm_get_vcpu(running_vm, 2)),
		  vm_get_vcpu(blocked_vm, 2));
	EXPECT_EQ(hf_ipi_get_pending_target_vcpu(vm_get_vcpu(running_vm, 3)),
		  vm_get_vcpu(preempted_vm, 3));
}

/**
 * Multiple services targeting IPIs to CPU0 are both pending.
 */
TEST_F(ipi, multiple_services_to_same_cpu)
{
	struct_vm *running_vm = ipi::test_vm[0];
	struct_vm *waiting_vm = ipi::test_vm[1];
	struct_vm *blocked_vm = ipi::test_vm[2];
	struct_vm *preempted_vm = ipi::test_vm[3];

	hf_ipi_send_interrupt(running_vm, 0);
	hf_ipi_send_interrupt(waiting_vm, 0);
	hf_ipi_send_interrupt(blocked_vm, 0);
	hf_ipi_send_interrupt(preempted_vm, 0);

	EXPECT_EQ(hf_ipi_get_pending_target_vcpu(vm_get_vcpu(running_vm, 0)),
		  vm_get_vcpu(running_vm, 0));
	EXPECT_EQ(hf_ipi_get_pending_target_vcpu(vm_get_vcpu(running_vm, 0)),
		  vm_get_vcpu(waiting_vm, 0));
	EXPECT_EQ(hf_ipi_get_pending_target_vcpu(vm_get_vcpu(running_vm, 0)),
		  vm_get_vcpu(blocked_vm, 0));
	EXPECT_EQ(hf_ipi_get_pending_target_vcpu(vm_get_vcpu(running_vm, 0)),
		  vm_get_vcpu(preempted_vm, 0));
	EXPECT_EQ(hf_ipi_get_pending_target_vcpu(vm_get_vcpu(running_vm, 0)),
		  (struct vcpu *)NULL);
}

/**
 * Check if the same service sends an IPI to the same target_vcpu
 * multiple times it is only added to the list once and does not create
 * loops in the list.
 */
TEST_F(ipi, multiple_services_to_same_cpu_multiple_sends)
{
	struct_vm *running_vm = ipi::test_vm[0];
	struct_vm *waiting_vm = ipi::test_vm[1];

	hf_ipi_send_interrupt(running_vm, 0);
	hf_ipi_send_interrupt(waiting_vm, 0);
	hf_ipi_send_interrupt(running_vm, 0);

	EXPECT_EQ(hf_ipi_get_pending_target_vcpu(vm_get_vcpu(running_vm, 0)),
		  vm_get_vcpu(running_vm, 0));
	EXPECT_EQ(hf_ipi_get_pending_target_vcpu(vm_get_vcpu(running_vm, 0)),
		  vm_get_vcpu(waiting_vm, 0));
	EXPECT_EQ(hf_ipi_get_pending_target_vcpu(vm_get_vcpu(running_vm, 0)),
		  (struct vcpu *)NULL);
}

/**
 * Multiple services targeting IPIs to CPU0 are both pending and the running
 * vCPU is returned first.
 */
TEST_F(ipi, multiple_services_to_same_cpu_running_prioritized)
{
	struct_vm *running_vm = ipi::test_vm[0];
	struct_vm *waiting_vm = ipi::test_vm[1];
	struct_vm *blocked_vm = ipi::test_vm[2];
	struct_vm *preempted_vm = ipi::test_vm[3];

	hf_ipi_send_interrupt(waiting_vm, 0);
	hf_ipi_send_interrupt(blocked_vm, 0);
	hf_ipi_send_interrupt(preempted_vm, 0);
	hf_ipi_send_interrupt(running_vm, 0);

	EXPECT_EQ(hf_ipi_get_pending_target_vcpu(vm_get_vcpu(running_vm, 0)),
		  vm_get_vcpu(running_vm, 0));
	EXPECT_EQ(hf_ipi_get_pending_target_vcpu(vm_get_vcpu(running_vm, 0)),
		  vm_get_vcpu(waiting_vm, 0));
	EXPECT_EQ(hf_ipi_get_pending_target_vcpu(vm_get_vcpu(running_vm, 0)),
		  vm_get_vcpu(blocked_vm, 0));
	EXPECT_EQ(hf_ipi_get_pending_target_vcpu(vm_get_vcpu(running_vm, 0)),
		  vm_get_vcpu(preempted_vm, 0));
	EXPECT_EQ(hf_ipi_get_pending_target_vcpu(vm_get_vcpu(running_vm, 0)),
		  (struct vcpu *)NULL);
}

/**
 * Multiple services targeting IPIs to CPU0 are both pending and the running
 * vCPU is returned first.
 */
TEST_F(ipi, multiple_services_to_same_cpu_full_handle)
{
	struct_vm *running_vm = ipi::test_vm[0];
	struct_vm *waiting_vm = ipi::test_vm[1];
	struct_vm *blocked_vm = ipi::test_vm[2];
	struct_vm *preempted_vm = ipi::test_vm[3];

	struct vcpu *top_priority_vcpu;
	struct vcpu_locked vcpu_locked;
	constexpr size_t test_service_count = 4;
	struct_vm *test_service[test_service_count] = {
		waiting_vm, blocked_vm, preempted_vm, running_vm};

	for (size_t i = 0; i < test_service_count; i++) {
		for (size_t j = 0; j < MAX_CPUS; j++) {
			hf_ipi_send_interrupt(test_service[i], j);
		}
	}

	/* Handle the IPI on all CPUs and do some inital checks. */
	for (size_t i = 0; i < MAX_CPUS; i++) {
		top_priority_vcpu = hf_ipi_get_pending_target_vcpu(
			vm_get_vcpu(running_vm, i));
		vcpu_locked = vcpu_lock(top_priority_vcpu);
		/*
		 * Check running service is returned as the top priority vCPU.
		 */
		EXPECT_EQ(top_priority_vcpu, vm_get_vcpu(running_vm, i));
		/* Run IPI handle on CPU0. */
		hf_ipi_handle(vcpu_locked);
		/*
		 * Since there is a running vCPU with a pending IPI when handing
		 * the WAITING vCPU we should have set the SRI to be delayed.
		 * Check this is the case.
		 */
		EXPECT_TRUE(top_priority_vcpu->cpu->is_sri_delayed);
		vcpu_unlock(&vcpu_locked);
	}

	for (size_t i = 0; i < test_service_count; i++) {
		struct vm_locked vm_locked = vm_lock(test_service[i]);
		uint16_t ids[FFA_NOTIFICATIONS_INFO_GET_MAX_IDS] = {0};
		uint32_t ids_count = 0;
		uint32_t lists_sizes[FFA_NOTIFICATIONS_INFO_GET_MAX_IDS] = {0};
		uint32_t lists_count = 0;
		enum notifications_info_get_state current_state = INIT;
		const bool is_from_vm = false;
		/*
		 * Check response of FFA_NOTIFICATION_INFO_GET. The ID should
		 * only be returned if the service is in the waiting state.
		 */
		vm_notifications_info_get_pending(
			vm_locked, is_from_vm, ids, &ids_count, lists_sizes,
			&lists_count, FFA_NOTIFICATIONS_INFO_GET_MAX_IDS,
			&current_state);
		/* In this test setup all vCPUs of a service are in the same
		 * state. */
		if (vm_get_vcpu(test_service[i], 0)->state ==
		    VCPU_STATE_WAITING) {
			EXPECT_EQ(ids_count, 6);
			EXPECT_EQ(lists_count, 2);
			EXPECT_EQ(lists_sizes[0], 3);
			EXPECT_EQ(lists_sizes[1], 1);
			EXPECT_EQ(ids[0], test_service[i]->id);
			EXPECT_EQ(ids[1], 0);
			EXPECT_EQ(ids[2], 1);
			EXPECT_EQ(ids[3], 2);
			EXPECT_EQ(ids[4], test_service[i]->id);
			EXPECT_EQ(ids[5], 3);
		} else {
			EXPECT_EQ(ids_count, 0);
			EXPECT_EQ(lists_count, 0);
		}

		for (size_t j = 0; j < MAX_CPUS; j++) {
			/* Check the IPI interrupt is pending. */
			struct vcpu *vcpu = vm_get_vcpu(test_service[i], j);
			vcpu_locked = vcpu_lock(vcpu);
			EXPECT_EQ(vcpu_virt_interrupt_get_pending_and_enabled(
					  vcpu_locked),
				  HF_IPI_INTID);
			vcpu_unlock(&vcpu_locked);
		}
		vm_unlock(&vm_locked);
	}

	for (size_t i = 0; i < MAX_CPUS; i++) {
		/* Check that there are no more vCPUs with pending IPIs */
		EXPECT_EQ(hf_ipi_get_pending_target_vcpu(
				  vm_get_vcpu(running_vm, i)),
			  (struct vcpu *)NULL);
	}
}
} /* namespace */
