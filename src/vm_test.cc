/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include <gmock/gmock.h>

extern "C" {
#include "hf/check.h"
#include "hf/list.h"
#include "hf/mpool.h"
#include "hf/timer_mgmt.h"
#include "hf/vm.h"
}

#include <list>
#include <memory>
#include <span>
#include <vector>

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

constexpr size_t TEST_HEAP_SIZE = PAGE_SIZE * 64;
const int TOP_LEVEL = arch_mm_stage2_max_level();

class vm : public ::testing::Test
{
       protected:
	static std::unique_ptr<uint8_t[]> test_heap;

	struct mpool ppool;

	void SetUp() override
	{
		if (!test_heap) {
			/*
			 * TODO: replace with direct use of stdlib allocator so
			 * sanitizers are more effective.
			 */
			test_heap = std::make_unique<uint8_t[]>(TEST_HEAP_SIZE);
			mpool_init(&ppool, sizeof(struct mm_page_table));
			mpool_add_chunk(&ppool, test_heap.get(),
					TEST_HEAP_SIZE);
		}
	}

       public:
	static bool BootOrderSmallerThan(struct_vm *vm1, struct_vm *vm2)
	{
		return vm1->boot_order < vm2->boot_order;
	}
};

std::unique_ptr<uint8_t[]> vm::test_heap;

/**
 * If nothing is mapped, unmapping the hypervisor has no effect.
 */
TEST_F(vm, vm_unmap_hypervisor_not_mapped)
{
	struct_vm *vm;
	struct vm_locked vm_locked;

	/* TODO: check ptable usage (security state?) */
	EXPECT_TRUE(vm_init_next(1, &ppool, &vm, false, 0));
	vm_locked = vm_lock(vm);
	ASSERT_TRUE(mm_vm_init(&vm->ptable, vm->id, &ppool));
	EXPECT_TRUE(vm_unmap_hypervisor(vm_locked, &ppool));
	EXPECT_THAT(
		mm_test::get_ptable(vm->ptable),
		AllOf(SizeIs(4), Each(Each(arch_mm_absent_pte(TOP_LEVEL)))));
	mm_vm_fini(&vm->ptable, &ppool);
	vm_unlock(&vm_locked);
}

/**
 * Validate the "boot_list" is created properly, according to vm's "boot_order"
 * field.
 */
TEST_F(vm, vm_boot_order)
{
	struct_vm *vm_cur;
	struct_vcpu *vcpu;
	std::list<struct_vm *> expected_final_order;

	/*
	 * Insertion when no call to "vcpu_update_boot" has been made yet.
	 * The "boot_list" is expected to be empty.
	 */
	EXPECT_TRUE(vm_init_next(1, &ppool, &vm_cur, false, 0));
	vm_cur->boot_order = 3;
	vcpu = vm_get_vcpu(vm_cur, 0);
	vcpu_update_boot(vcpu);
	expected_final_order.push_back(vm_cur);

	EXPECT_EQ(vcpu_get_boot_vcpu()->vm->id, vm_cur->id);

	/* Insertion at the head of the boot list */
	EXPECT_TRUE(vm_init_next(1, &ppool, &vm_cur, false, 0));
	vm_cur->boot_order = 1;
	vcpu = vm_get_vcpu(vm_cur, 0);
	vcpu_update_boot(vcpu);
	expected_final_order.push_back(vm_cur);

	EXPECT_EQ(vcpu_get_boot_vcpu()->vm->id, vm_cur->id);

	/* Insertion of two in the middle of the boot list */
	for (uint32_t i = 0; i < 2; i++) {
		EXPECT_TRUE(vm_init_next(1, &ppool, &vm_cur, false, 0));
		vm_cur->boot_order = 2;
		vcpu = vm_get_vcpu(vm_cur, 0);
		vcpu_update_boot(vcpu);
		expected_final_order.push_back(vm_cur);
	}

	/*
	 * Insertion in the end of the list.
	 * This tests shares the data with "vm_unmap_hypervisor_not_mapped".
	 * As such, a VM is expected to have been initialized before this
	 * test, with ID 1 and boot_order 0.
	 */
	vm_cur = vm_find(1);
	EXPECT_FALSE(vm_cur == NULL);
	vcpu = vm_get_vcpu(vm_cur, 0);
	vcpu_update_boot(vcpu);
	expected_final_order.push_back(vm_cur);

	/*
	 * Number of VMs initialized should be the same as in the
	 * "expected_final_order", before the final verification.
	 */
	EXPECT_EQ(expected_final_order.size(), vm_get_count())
		<< "Something went wrong with the test itself...\n";

	/* Sort VMs from lower to higher "boot_order" field.*/
	expected_final_order.sort(vm::BootOrderSmallerThan);

	std::list<struct_vm *>::iterator it;
	vcpu = vcpu_get_boot_vcpu();
	for (it = expected_final_order.begin();
	     it != expected_final_order.end(); it++) {
		EXPECT_TRUE(vcpu != NULL);
		EXPECT_EQ((*it)->id, vcpu->vm->id);
		vcpu = vcpu_get_next_boot(vcpu);
	}
}

TEST_F(vm, vcpu_arch_timer)
{
	const cpu_id_t cpu_ids[2] = {0, 1};
	struct_vcpu *vm0_vcpu;
	struct_vcpu *vm1_vcpu;
	struct_vcpu *deadline_vcpu;
	struct_vcpu *target_vcpu;
	struct vcpu_locked vcpu_locked;
	struct cpu *cpu0;
	struct cpu *cpu1;

	/* Initialie CPU module with two physical CPUs. */
	cpu_module_init(cpu_ids, 2);
	cpu0 = cpu_find_index(0);
	cpu1 = cpu_find_index(1);

	/* Two UP endpoints are deployed for this test. */
	CHECK(vm_get_count() >= 2);
	vm0_vcpu = vm_get_vcpu(vm_find_index(0), 0);
	vm1_vcpu = vm_get_vcpu(vm_find_index(1), 0);

	/* The execution context of each VM is scheduled on CPU0. */
	vm0_vcpu->cpu = cpu0;
	vm1_vcpu->cpu = cpu0;

	/*
	 * Enable the timer peripheral for each vCPU and setup an arbitraty
	 * countdown value.
	 */
	vm0_vcpu->regs.arch_timer.cval = 555555;
	vm1_vcpu->regs.arch_timer.cval = 999999;
	vm0_vcpu->regs.arch_timer.ctl = 1;
	vm1_vcpu->regs.arch_timer.ctl = 1;

	/* No vCPU is being tracked through either timer list. */
	deadline_vcpu = timer_find_vcpu_nearest_deadline(cpu0);
	EXPECT_TRUE(deadline_vcpu == NULL);
	deadline_vcpu = timer_find_vcpu_nearest_deadline(cpu1);
	EXPECT_TRUE(deadline_vcpu == NULL);

	/* vCPU of VM0 and VM1 are being added to the list. */
	timer_vcpu_manage(vm0_vcpu);
	timer_vcpu_manage(vm1_vcpu);

	deadline_vcpu = timer_find_vcpu_nearest_deadline(cpu0);
	EXPECT_EQ(deadline_vcpu, vm0_vcpu);

	/* Remove one of the vCPUs from the CPU0 list. */
	vm0_vcpu->regs.arch_timer.cval = 0;
	vm0_vcpu->regs.arch_timer.ctl = 0;
	timer_vcpu_manage(vm0_vcpu);

	/* This leaves one vCPU entry on CPU0 list. */
	deadline_vcpu = timer_find_vcpu_nearest_deadline(cpu0);
	EXPECT_EQ(deadline_vcpu, vm1_vcpu);

	/* Attempt to migrate VM1 vCPU from CPU0 to CPU1. */
	vcpu_locked = vcpu_lock(vm1_vcpu);
	timer_migrate_to_other_cpu(cpu1, vcpu_locked);
	vcpu_unlock(&vcpu_locked);

	/*
	 * After migration, ensure the list is empty on CPU0 but non-empty on
	 * CPU1.
	 */
	deadline_vcpu = timer_find_vcpu_nearest_deadline(cpu0);
	EXPECT_TRUE(deadline_vcpu == NULL);

	/*
	 * vCPU of VM1 is now running on CPU1. It must be the target vCPU when
	 * the timer has expired.
	 */
	target_vcpu = timer_find_target_vcpu(vm1_vcpu);
	EXPECT_EQ(target_vcpu, vm1_vcpu);
}

/**
 * Validates updates and check functions for binding notifications to endpoints.
 */
TEST_F(vm, vm_notifications_bind_diff_senders)
{
	struct_vm *current_vm = nullptr;
	struct vm_locked current_vm_locked;
	std::vector<struct_vm *> dummy_senders;
	ffa_notifications_bitmap_t bitmaps[] = {
		0x00000000FFFFFFFFU, 0xFFFFFFFF00000000U, 0x0000FFFFFFFF0000U};
	bool is_from_vm = true;

	/* For the subsequent tests three VMs are used. */
	CHECK(vm_get_count() >= 3);

	current_vm = vm_find_index(0);

	dummy_senders.push_back(vm_find_index(1));
	dummy_senders.push_back(vm_find_index(2));

	current_vm_locked = vm_lock(current_vm);

	for (unsigned int i = 0; i < 2; i++) {
		/* Validate bindings condition after initialization. */
		EXPECT_TRUE(vm_notifications_validate_binding(
			current_vm_locked, is_from_vm, HF_INVALID_VM_ID,
			bitmaps[i], false));

		/*
		 * Validate bind related operations. For this test considering
		 * only global notifications.
		 */
		vm_notifications_update_bindings(current_vm_locked, is_from_vm,
						 dummy_senders[i]->id,
						 bitmaps[i], false);

		EXPECT_TRUE(vm_notifications_validate_binding(
			current_vm_locked, is_from_vm, dummy_senders[i]->id,
			bitmaps[i], false));

		EXPECT_FALSE(vm_notifications_validate_binding(
			current_vm_locked, is_from_vm, dummy_senders[1 - i]->id,
			bitmaps[i], false));

		EXPECT_FALSE(vm_notifications_validate_binding(
			current_vm_locked, is_from_vm, dummy_senders[i]->id,
			bitmaps[1 - i], false));

		EXPECT_FALSE(vm_notifications_validate_binding(
			current_vm_locked, is_from_vm, dummy_senders[i]->id,
			bitmaps[2], false));
	}

	/** Clean up bind for other tests. */
	vm_notifications_update_bindings(current_vm_locked, is_from_vm, 0,
					 bitmaps[0], false);
	vm_notifications_update_bindings(current_vm_locked, is_from_vm, 0,
					 bitmaps[1], false);

	vm_unlock(&current_vm_locked);
}

/**
 * Validates updates and check functions for binding notifications, namely the
 * configuration of bindings of global and per-vCPU notifications.
 */
TEST_F(vm, vm_notification_bind_per_vcpu_vs_global)
{
	struct_vm *current_vm;
	struct vm_locked current_vm_locked;
	struct_vm *dummy_sender;
	ffa_notifications_bitmap_t global = 0x00000000FFFFFFFFU;
	ffa_notifications_bitmap_t per_vcpu = ~global;
	bool is_from_vm = true;

	CHECK(vm_get_count() >= 2);

	current_vm = vm_find_index(0);

	dummy_sender = vm_find_index(1);

	current_vm_locked = vm_lock(current_vm);

	vm_notifications_update_bindings(current_vm_locked, is_from_vm,
					 dummy_sender->id, global, false);
	vm_notifications_update_bindings(current_vm_locked, is_from_vm,
					 dummy_sender->id, per_vcpu, true);

	/* Check validation of global notifications bindings. */
	EXPECT_TRUE(vm_notifications_validate_binding(
		current_vm_locked, is_from_vm, dummy_sender->id, global,
		false));

	/* Check validation of per-vCPU notifications bindings. */
	EXPECT_TRUE(vm_notifications_validate_binding(
		current_vm_locked, is_from_vm, dummy_sender->id, per_vcpu,
		true));

	/**
	 * Check that global notifications are not validated as per-vCPU, and
	 * vice-versa.
	 */
	EXPECT_FALSE(vm_notifications_validate_binding(
		current_vm_locked, is_from_vm, dummy_sender->id, global, true));
	EXPECT_FALSE(vm_notifications_validate_binding(
		current_vm_locked, is_from_vm, dummy_sender->id, per_vcpu,
		false));
	EXPECT_FALSE(vm_notifications_validate_binding(
		current_vm_locked, is_from_vm, dummy_sender->id,
		global | per_vcpu, true));
	EXPECT_FALSE(vm_notifications_validate_binding(
		current_vm_locked, is_from_vm, dummy_sender->id,
		global | per_vcpu, false));

	/** Undo the bindings */
	vm_notifications_update_bindings(current_vm_locked, is_from_vm, 0,
					 global, false);
	EXPECT_TRUE(vm_notifications_validate_binding(
		current_vm_locked, is_from_vm, 0, global, false));

	vm_notifications_update_bindings(current_vm_locked, is_from_vm, 0,
					 per_vcpu, false);
	EXPECT_TRUE(vm_notifications_validate_binding(
		current_vm_locked, is_from_vm, 0, per_vcpu, false));

	vm_unlock(&current_vm_locked);
}

/**
 * Validates accesses to notifications bitmaps.
 */
TEST_F(vm, vm_notifications_set_and_get)
{
	struct_vm *current_vm;
	struct vm_locked current_vm_locked;
	struct_vm *dummy_sender;
	ffa_notifications_bitmap_t global = 0x00000000FFFFFFFFU;
	ffa_notifications_bitmap_t per_vcpu = ~global;
	ffa_notifications_bitmap_t ret;
	const unsigned int vcpu_idx = 0;
	struct notifications *notifications;
	const bool is_from_vm = true;

	CHECK(vm_get_count() >= 2);

	current_vm = vm_find_index(0);
	dummy_sender = vm_find_index(1);

	notifications = &current_vm->notifications.from_vm;
	current_vm_locked = vm_lock(current_vm);

	vm_notifications_update_bindings(current_vm_locked, is_from_vm,
					 dummy_sender->id, global, false);
	vm_notifications_update_bindings(current_vm_locked, is_from_vm,
					 dummy_sender->id, per_vcpu, true);

	/*
	 * Validate get notifications bitmap for global notifications.
	 */
	vm_notifications_partition_set_pending(current_vm_locked, is_from_vm,
					       global, 0ull, false);

	ret = vm_notifications_partition_get_pending(current_vm_locked,
						     is_from_vm, 0ull);
	EXPECT_EQ(ret, global);
	EXPECT_EQ(notifications->global.pending, 0ull);

	/*
	 * Validate get notifications bitmap for per-vCPU notifications.
	 */
	vm_notifications_partition_set_pending(current_vm_locked, is_from_vm,
					       per_vcpu, vcpu_idx, true);

	ret = vm_notifications_partition_get_pending(current_vm_locked,
						     is_from_vm, vcpu_idx);
	EXPECT_EQ(ret, per_vcpu);
	EXPECT_EQ(notifications->per_vcpu[vcpu_idx].pending, 0ull);

	/*
	 * Validate that getting notifications for a specific vCPU also returns
	 * global notifications.
	 */
	vm_notifications_partition_set_pending(current_vm_locked, is_from_vm,
					       per_vcpu, vcpu_idx, true);
	vm_notifications_partition_set_pending(current_vm_locked, is_from_vm,
					       global, 0ull, false);

	ret = vm_notifications_partition_get_pending(current_vm_locked,
						     is_from_vm, vcpu_idx);
	EXPECT_EQ(ret, per_vcpu | global);
	EXPECT_EQ(notifications->per_vcpu[vcpu_idx].pending, 0ull);
	EXPECT_EQ(notifications->global.pending, 0ull);

	/** Undo the binding */
	vm_notifications_update_bindings(current_vm_locked, is_from_vm, 0ull,
					 global, false);
	vm_notifications_update_bindings(current_vm_locked, is_from_vm, 0ull,
					 per_vcpu, true);
	vm_unlock(&current_vm_locked);
}

/**
 * Validates simple getting of notifications info for global notifications.
 */
TEST_F(vm, vm_notifications_info_get_global)
{
	ffa_notifications_bitmap_t to_set = 0xFU;
	ffa_notifications_bitmap_t got;

	/**
	 * Following set of variables that are also expected to be used when
	 * handling FFA_NOTIFICATION_INFO_GET.
	 */
	uint16_t ids[FFA_NOTIFICATIONS_INFO_GET_MAX_IDS] = {0};
	uint32_t lists_sizes[FFA_NOTIFICATIONS_INFO_GET_MAX_IDS] = {0};
	uint32_t ids_count = 0;
	uint32_t lists_count = 0;
	enum notifications_info_get_state current_state = INIT;

	CHECK(vm_get_count() >= 2);

	for (unsigned int i = 0; i < 2; i++) {
		struct_vm *current_vm = vm_find_index(0);
		struct vm_locked current_vm_locked = vm_lock(current_vm);
		struct notifications *notifications =
			&current_vm->notifications.from_sp;
		const bool is_from_vm = false;

		vm_notifications_partition_set_pending(
			current_vm_locked, is_from_vm, to_set, 0, false);

		vm_notifications_info_get_pending(
			current_vm_locked, is_from_vm, ids, &ids_count,
			lists_sizes, &lists_count,
			FFA_NOTIFICATIONS_INFO_GET_MAX_IDS, &current_state);

		/*
		 * Here the number of IDs and list count should be the same.
		 * As we are testing with Global notifications, this is
		 * expected.
		 */
		EXPECT_EQ(ids_count, i + 1);
		EXPECT_EQ(lists_count, i + 1);
		EXPECT_EQ(lists_sizes[i], 0);
		EXPECT_EQ(to_set, notifications->global.info_get_retrieved);

		/* Action must be reset to initial state for each VM. */
		current_state = INIT;

		/*
		 * Check that getting pending notifications gives the expected
		 * return and cleans the 'pending' and 'info_get_retrieved'
		 * bitmaps.
		 */
		got = vm_notifications_partition_get_pending(current_vm_locked,
							     is_from_vm, 0);
		EXPECT_EQ(got, to_set);

		EXPECT_EQ(notifications->global.info_get_retrieved, 0U);
		EXPECT_EQ(notifications->global.pending, 0U);

		vm_unlock(&current_vm_locked);
	}
}

/**
 * Validates simple getting of notifications info for per-vCPU notifications.
 */
TEST_F(vm, vm_notifications_info_get_per_vcpu)
{
	const ffa_notifications_bitmap_t per_vcpu = 0xFU;
	ffa_notifications_bitmap_t got;

	/*
	 * Following set of variables that are also expected to be used when
	 * handling ffa_notification_info_get.
	 */
	uint16_t ids[FFA_NOTIFICATIONS_INFO_GET_MAX_IDS] = {0};
	uint32_t ids_count = 0;
	uint32_t lists_sizes[FFA_NOTIFICATIONS_INFO_GET_MAX_IDS] = {0};
	uint32_t lists_count = 0;
	enum notifications_info_get_state current_state = INIT;

	CHECK(vm_get_count() >= 2);

	for (unsigned int i = 0; i < 2; i++) {
		struct_vm *current_vm = vm_find_index(0);
		struct vm_locked current_vm_locked = vm_lock(current_vm);
		struct notifications *notifications =
			&current_vm->notifications.from_sp;
		const bool is_from_vm = false;

		vm_notifications_partition_set_pending(
			current_vm_locked, is_from_vm, per_vcpu, 0, true);

		vm_notifications_info_get_pending(
			current_vm_locked, is_from_vm, ids, &ids_count,
			lists_sizes, &lists_count,
			FFA_NOTIFICATIONS_INFO_GET_MAX_IDS, &current_state);

		/*
		 * Here the number of IDs and list count should be the same.
		 * As we are testing with Global notifications, this is
		 * expected.
		 */
		EXPECT_EQ(ids_count, (i + 1) * 2);
		EXPECT_EQ(lists_count, i + 1);
		EXPECT_EQ(lists_sizes[i], 1);
		EXPECT_EQ(per_vcpu,
			  notifications->per_vcpu[0].info_get_retrieved);

		/* Action must be reset to initial state for each VM. */
		current_state = INIT;

		/*
		 * Check that getting pending notifications gives the expected
		 * return and cleans the 'pending' and 'info_get_retrieved'
		 * bitmaps.
		 */
		got = vm_notifications_partition_get_pending(current_vm_locked,
							     is_from_vm, 0);
		EXPECT_EQ(got, per_vcpu);

		EXPECT_EQ(notifications->per_vcpu[0].info_get_retrieved, 0U);
		EXPECT_EQ(notifications->per_vcpu[0].pending, 0U);

		vm_unlock(&current_vm_locked);
	}
}

/**
 * Validate getting of notifications information if all VCPUs have notifications
 * pending.
 */
TEST_F(vm, vm_notifications_info_get_per_vcpu_all_vcpus)
{
	struct_vm *current_vm = nullptr;
	struct vm_locked current_vm_locked;
	const ffa_vcpu_count_t vcpu_count = MAX_CPUS;
	ffa_notifications_bitmap_t got;
	const ffa_notifications_bitmap_t global = 0xF0000;

	/*
	 * Following set of variables that are also expected to be used when
	 * handling ffa_notification_info_get.
	 */
	struct notifications *notifications;
	const bool is_from_sp = false;
	uint16_t ids[FFA_NOTIFICATIONS_INFO_GET_MAX_IDS] = {0};
	uint32_t ids_count = 0;
	uint32_t lists_sizes[FFA_NOTIFICATIONS_INFO_GET_MAX_IDS] = {0};
	uint32_t lists_count = 0;
	enum notifications_info_get_state current_state = INIT;

	EXPECT_TRUE(vm_init_next(vcpu_count, &ppool, &current_vm, false, 0));
	current_vm_locked = vm_lock(current_vm);
	notifications = &current_vm->notifications.from_sp;

	for (unsigned int i = 0; i < vcpu_count; i++) {
		vm_notifications_partition_set_pending(
			current_vm_locked, is_from_sp, FFA_NOTIFICATION_MASK(i),
			i, true);
	}

	/*
	 * Adding a global notification should not change the list of IDs,
	 * because global notifications only require the VM ID to be included in
	 * the list, at least once.
	 */
	vm_notifications_partition_set_pending(current_vm_locked, is_from_sp,
					       global, 0, false);

	vm_notifications_info_get_pending(current_vm_locked, is_from_sp, ids,
					  &ids_count, lists_sizes, &lists_count,
					  FFA_NOTIFICATIONS_INFO_GET_MAX_IDS,
					  &current_state);

	/*
	 * This test has been conceived for the expected MAX_CPUS 4.
	 * All VCPUs have notifications of the same VM, to be broken down in 2
	 * lists with 3 VCPU IDs, and 1 VCPU ID respectively.
	 * The list of IDs should look like: {<vm_id>, 0, 1, 2, <vm_id>, 3}.
	 */
	CHECK(MAX_CPUS == 4);
	EXPECT_EQ(ids_count, 6U);
	EXPECT_EQ(lists_count, 2U);
	EXPECT_EQ(lists_sizes[0], 3);
	EXPECT_EQ(lists_sizes[1], 1);

	for (unsigned int i = 0; i < vcpu_count; i++) {
		got = vm_notifications_partition_get_pending(current_vm_locked,
							     is_from_sp, i);

		/*
		 * The first call to
		 * vm_notifications_partition_get_pending should also
		 * include the global notifications on the return.
		 */
		ffa_notifications_bitmap_t to_check =
			(i != 0) ? FFA_NOTIFICATION_MASK(i)
				 : FFA_NOTIFICATION_MASK(i) | global;

		EXPECT_EQ(got, to_check);

		EXPECT_EQ(notifications->per_vcpu[i].pending, 0);
		EXPECT_EQ(notifications->per_vcpu[i].info_get_retrieved, 0);
	}

	vm_unlock(&current_vm_locked);
}

/**
 * Validate change of state from 'vm_notifications_info_get_pending', when the
 * list of IDs is full.
 */
TEST_F(vm, vm_notifications_info_get_full_per_vcpu)
{
	struct_vm *current_vm = vm_find_index(0);
	struct vm_locked current_vm_locked = vm_lock(current_vm);
	struct notifications *notifications =
		&current_vm->notifications.from_sp;
	const bool is_from_vm = false;
	ffa_notifications_bitmap_t got = 0;

	/*
	 * Following set of variables that are also expected to be used when
	 * handling ffa_notification_info_get.
	 * For this 'ids_count' has been initialized such that it indicates
	 * there is no space in the list for a per-vCPU notification (VM ID and
	 * VCPU ID).
	 */
	uint16_t ids[FFA_NOTIFICATIONS_INFO_GET_MAX_IDS] = {0};
	uint32_t ids_count = FFA_NOTIFICATIONS_INFO_GET_MAX_IDS - 1;
	uint32_t lists_sizes[FFA_NOTIFICATIONS_INFO_GET_MAX_IDS] = {0};
	uint32_t lists_count = 10;
	enum notifications_info_get_state current_state = INIT;
	CHECK(vm_get_count() >= 2);

	vm_notifications_partition_set_pending(current_vm_locked, is_from_vm,
					       FFA_NOTIFICATION_MASK(1), 0,
					       true);

	/* Call function to get notifications info, with only per-vCPU set. */
	vm_notifications_info_get_pending(current_vm_locked, is_from_vm, ids,
					  &ids_count, lists_sizes, &lists_count,
					  FFA_NOTIFICATIONS_INFO_GET_MAX_IDS,
					  &current_state);

	/*
	 * Verify that as soon as there isn't space to do the required
	 * insertion in the list, the
	 * 'vm_notifications_partition_get_pending' returns and changes
	 * list state to FULL. In this case returning, because it would need to
	 * add two IDs (VM ID and VCPU ID).
	 */
	EXPECT_EQ(current_state, FULL);
	EXPECT_EQ(ids_count, FFA_NOTIFICATIONS_INFO_GET_MAX_IDS - 1);
	EXPECT_EQ(notifications->per_vcpu[0].info_get_retrieved, 0U);

	/*
	 * At this point there is still room for the information of a global
	 * notification (only VM ID to be added). Reset 'current_state'
	 * for the insertion to happen at the last position of the array.
	 */
	current_state = INIT;

	/* Setting global notification */
	vm_notifications_partition_set_pending(current_vm_locked, is_from_vm,
					       FFA_NOTIFICATION_MASK(2), 0,
					       false);

	vm_notifications_info_get_pending(current_vm_locked, is_from_vm, ids,
					  &ids_count, lists_sizes, &lists_count,
					  FFA_NOTIFICATIONS_INFO_GET_MAX_IDS,
					  &current_state);

	/*
	 * Now List must be full, the set global notification must be part of
	 * 'info_get_retrieved', and the 'current_state' should be set to FULL
	 * due to the pending per-vCPU notification in VCPU 0.
	 */
	EXPECT_EQ(ids_count, FFA_NOTIFICATIONS_INFO_GET_MAX_IDS);
	EXPECT_EQ(current_state, FULL);
	EXPECT_EQ(notifications->global.info_get_retrieved,
		  FFA_NOTIFICATION_MASK(2));

	got = vm_notifications_partition_get_pending(current_vm_locked,
						     is_from_vm, 0);
	EXPECT_EQ(got, FFA_NOTIFICATION_MASK(1) | FFA_NOTIFICATION_MASK(2));

	vm_unlock(&current_vm_locked);
}

TEST_F(vm, vm_notifications_info_get_full_global)
{
	struct_vm *current_vm = vm_find_index(0);
	struct vm_locked current_vm_locked = vm_lock(current_vm);
	ffa_notifications_bitmap_t got;
	struct notifications *notifications;
	const bool is_from_vm = false;
	/*
	 * Following set of variables that are also expected to be used when
	 * handling ffa_notification_info_get.
	 * For this 'ids_count' has been initialized such that it indicates
	 * there is no space in the list for a global notification (VM ID only).
	 */
	uint16_t ids[FFA_NOTIFICATIONS_INFO_GET_MAX_IDS] = {0};
	uint32_t ids_count = FFA_NOTIFICATIONS_INFO_GET_MAX_IDS;
	uint32_t lists_sizes[FFA_NOTIFICATIONS_INFO_GET_MAX_IDS] = {0};
	uint32_t lists_count = 10;
	enum notifications_info_get_state current_state = INIT;

	CHECK(vm_get_count() >= 1);

	current_vm = vm_find_index(0);

	notifications = &current_vm->notifications.from_sp;

	/* Set global notification. */
	vm_notifications_partition_set_pending(current_vm_locked, is_from_vm,
					       FFA_NOTIFICATION_MASK(10), 0,
					       false);

	/* Get notifications info for the given notifications. */
	vm_notifications_info_get_pending(current_vm_locked, is_from_vm, ids,
					  &ids_count, lists_sizes, &lists_count,
					  FFA_NOTIFICATIONS_INFO_GET_MAX_IDS,
					  &current_state);

	/* Expect 'info_get_retrieved' bitmap to be 0. */
	EXPECT_EQ(notifications->global.info_get_retrieved, 0U);
	EXPECT_EQ(notifications->global.pending, FFA_NOTIFICATION_MASK(10));
	EXPECT_EQ(ids_count, FFA_NOTIFICATIONS_INFO_GET_MAX_IDS);
	EXPECT_EQ(current_state, FULL);

	got = vm_notifications_partition_get_pending(current_vm_locked,
						     is_from_vm, 0);
	EXPECT_EQ(got, FFA_NOTIFICATION_MASK(10));

	vm_unlock(&current_vm_locked);
}

TEST_F(vm, vm_notifications_info_get_from_framework)
{
	struct vm_locked vm_locked = vm_lock(vm_find_index(0));
	uint16_t ids[FFA_NOTIFICATIONS_INFO_GET_MAX_IDS] = {0};
	uint32_t ids_count = 0;
	uint32_t lists_sizes[FFA_NOTIFICATIONS_INFO_GET_MAX_IDS] = {0};
	uint32_t lists_count = 0;

	vm_notifications_framework_set_pending(vm_locked, 0x1U);

	/* Get notifications info for the given notifications. */
	vm_notifications_info_get(vm_locked, ids, &ids_count, lists_sizes,
				  &lists_count,
				  FFA_NOTIFICATIONS_INFO_GET_MAX_IDS);

	EXPECT_EQ(ids[0], vm_locked.vm->id);
	EXPECT_EQ(ids_count, 1);
	EXPECT_EQ(lists_sizes[0], 0);
	EXPECT_EQ(lists_count, 1);

	EXPECT_EQ(vm_notifications_framework_get_pending(vm_locked), 0x1U);

	vm_unlock(&vm_locked);
}

/**
 * Validates simple getting of notifications info for pending IPI.
 */
TEST_F(vm, vm_notifications_info_get_ipi)
{
	/*
	 * Following set of variables that are also expected to be used when
	 * handling ffa_notification_info_get.
	 */
	uint16_t ids[FFA_NOTIFICATIONS_INFO_GET_MAX_IDS] = {0};
	uint32_t ids_count = 0;
	uint32_t lists_sizes[FFA_NOTIFICATIONS_INFO_GET_MAX_IDS] = {0};
	uint32_t lists_count = 0;
	enum notifications_info_get_state current_state = INIT;
	struct_vm *current_vm = vm_find_index(5);
	struct vcpu *target_vcpu = vm_get_vcpu(current_vm, 1);
	struct interrupts *interrupts = &target_vcpu->interrupts;
	const bool is_from_vm = false;
	struct vm_locked current_vm_locked = vm_lock(current_vm);

	EXPECT_TRUE(current_vm->vcpu_count >= 2);

	vcpu_virt_interrupt_set_pending(interrupts, HF_IPI_INTID);

	vm_notifications_info_get_pending(current_vm_locked, is_from_vm, ids,
					  &ids_count, lists_sizes, &lists_count,
					  FFA_NOTIFICATIONS_INFO_GET_MAX_IDS,
					  &current_state);

	EXPECT_EQ(ids_count, 2);
	EXPECT_EQ(lists_count, 1);
	EXPECT_EQ(lists_sizes[0], 1);
	EXPECT_EQ(ids[0], current_vm->id);
	EXPECT_EQ(ids[1], 1);
	EXPECT_EQ(target_vcpu->ipi_info_get_retrieved, true);

	/* Check it is not retrieved multiple times. */
	current_state = INIT;
	ids[0] = 0;
	ids[1] = 0;
	ids_count = 0;
	lists_sizes[0] = 0;
	lists_count = 0;

	vm_notifications_info_get_pending(current_vm_locked, is_from_vm, ids,
					  &ids_count, lists_sizes, &lists_count,
					  FFA_NOTIFICATIONS_INFO_GET_MAX_IDS,
					  &current_state);
	EXPECT_EQ(ids_count, 0);
	EXPECT_EQ(lists_count, 0);
	EXPECT_EQ(lists_sizes[0], 0);

	vm_unlock(&current_vm_locked);
}

/**
 * Validates simple getting of notifications info for pending with IPI when
 * notification for the same vcpu is also pending.
 */
TEST_F(vm, vm_notifications_info_get_ipi_with_per_vcpu)
{
	/*
	 * Following set of variables that are also expected to be used when
	 * handling ffa_notification_info_get.
	 */
	uint16_t ids[FFA_NOTIFICATIONS_INFO_GET_MAX_IDS] = {0};
	uint32_t ids_count = 0;
	uint32_t lists_sizes[FFA_NOTIFICATIONS_INFO_GET_MAX_IDS] = {0};
	uint32_t lists_count = 0;
	enum notifications_info_get_state current_state = INIT;
	struct_vm *current_vm = vm_find_index(5);
	struct vcpu *target_vcpu = vm_get_vcpu(current_vm, 1);
	struct interrupts *interrupts = &target_vcpu->interrupts;
	const bool is_from_vm = false;
	struct vm_locked current_vm_locked = vm_lock(current_vm);

	EXPECT_TRUE(current_vm->vcpu_count >= 2);

	vcpu_virt_interrupt_set_pending(interrupts, HF_IPI_INTID);

	vm_notifications_partition_set_pending(current_vm_locked, is_from_vm,
					       true, 1, true);
	vm_notifications_info_get_pending(current_vm_locked, is_from_vm, ids,
					  &ids_count, lists_sizes, &lists_count,
					  FFA_NOTIFICATIONS_INFO_GET_MAX_IDS,
					  &current_state);

	EXPECT_EQ(ids_count, 2);
	EXPECT_EQ(lists_count, 1);
	EXPECT_EQ(lists_sizes[0], 1);
	EXPECT_EQ(ids[0], current_vm->id);
	EXPECT_EQ(ids[1], 1);
	EXPECT_EQ(target_vcpu->ipi_info_get_retrieved, true);

	/* Reset the state and values. */
	current_state = INIT;
	ids[0] = 0;
	ids[1] = 0;
	ids_count = 0;
	lists_sizes[0] = 0;
	lists_count = 0;

	vm_notifications_info_get_pending(current_vm_locked, is_from_vm, ids,
					  &ids_count, lists_sizes, &lists_count,
					  FFA_NOTIFICATIONS_INFO_GET_MAX_IDS,
					  &current_state);
	EXPECT_EQ(ids_count, 0);
	EXPECT_EQ(lists_count, 0);
	EXPECT_EQ(lists_sizes[0], 0);

	vm_unlock(&current_vm_locked);
}

/**
 * Validate that a mix of a pending IPI and notifcations are correctly
 * reported across vcpus.
 */
TEST_F(vm, vm_notifications_info_get_per_vcpu_all_vcpus_and_ipi)
{
	struct_vm *current_vm = vm_find_index(5);
	ffa_vcpu_count_t vcpu_count = current_vm->vcpu_count;
	CHECK(vcpu_count > 1);

	struct vm_locked current_vm_locked = vm_lock(current_vm);

	/*
	 * Following set of variables that are also expected to be used when
	 * handling ffa_notification_info_get.
	 */
	const bool is_from_vm = false;
	uint16_t ids[FFA_NOTIFICATIONS_INFO_GET_MAX_IDS] = {0};
	uint32_t ids_count = 0;
	uint32_t lists_sizes[FFA_NOTIFICATIONS_INFO_GET_MAX_IDS] = {0};
	uint32_t lists_count = 0;
	enum notifications_info_get_state current_state = INIT;
	struct vcpu *target_vcpu = vm_get_vcpu(current_vm, 0);
	struct interrupts *interrupts = &target_vcpu->interrupts;

	vcpu_virt_interrupt_set_pending(interrupts, HF_IPI_INTID);

	for (unsigned int i = 1; i < vcpu_count; i++) {
		vm_notifications_partition_set_pending(
			current_vm_locked, is_from_vm, FFA_NOTIFICATION_MASK(i),
			i, true);
	}

	vm_notifications_info_get_pending(current_vm_locked, is_from_vm, ids,
					  &ids_count, lists_sizes, &lists_count,
					  FFA_NOTIFICATIONS_INFO_GET_MAX_IDS,
					  &current_state);

	/*
	 * This test has been conceived for the expected MAX_CPUS 4.
	 * All VCPUs have notifications of the same VM, to be broken down in 2
	 * lists with 3 VCPU IDs, and 1 VCPU ID respectively.
	 * The list of IDs should look like: {<vm_id>, 0, 1, 2, <vm_id>, 3}.
	 */
	EXPECT_EQ(ids_count, 6U);
	EXPECT_EQ(lists_count, 2U);
	EXPECT_EQ(lists_sizes[0], 3);
	EXPECT_EQ(lists_sizes[1], 1);
	EXPECT_EQ(ids[0], current_vm->id);
	EXPECT_EQ(ids[1], 0);
	EXPECT_EQ(ids[2], 1);
	EXPECT_EQ(ids[3], 2);
	EXPECT_EQ(ids[4], current_vm->id);
	EXPECT_EQ(ids[5], 3);

	vm_unlock(&current_vm_locked);
}
} /* namespace */
