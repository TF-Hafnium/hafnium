/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include <gmock/gmock.h>

extern "C" {
#include "hf/arch/mm.h"

#include "hf/check.h"
#include "hf/mm.h"
#include "hf/plat/memory_alloc.h"
#include "hf/timer_mgmt.h"
#include "hf/vm.h"
}

#include <list>
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

const mm_level_t TOP_LEVEL = arch_mm_stage2_root_level() - 1;

class vm : public ::testing::Test
{
       protected:
	void SetUp() override
	{
		static bool allocator_initialized = false;

		if (!allocator_initialized) {
			memory_alloc_init();
			allocator_initialized = true;
		}
	}

       public:
	static bool BootOrderSmallerThan(struct_vm *vm1, struct_vm *vm2)
	{
		return vm1->boot_order < vm2->boot_order;
	}
};

/**
 * If nothing is mapped, unmapping the hypervisor has no effect.
 */
TEST_F(vm, vm_unmap_hypervisor_not_mapped)
{
	struct_vm *vm;
	struct vm_locked vm_locked;

	/* TODO: check ptable usage (security state?) */
	EXPECT_TRUE(vm_init_next(1, &vm, false, 0));
	vm_locked = vm_lock(vm);
	ASSERT_TRUE(mm_vm_init(&vm->ptable, vm->id));
	EXPECT_TRUE(vm_unmap_hypervisor(vm_locked));
	EXPECT_THAT(
		mm_test::get_ptable(vm->ptable),
		AllOf(SizeIs(4), Each(Each(arch_mm_absent_pte(TOP_LEVEL)))));
	mm_vm_fini(&vm->ptable);
	vm_unlock(&vm_locked);
}

/**
 * Validate the "boot_list" is created properly, according to vm's "boot_order"
 * field.
 */
TEST_F(vm, vm_boot_order)
{
	struct_vm *vm_cur;
	struct_vm *vm;
	std::list<struct_vm *> expected_final_order;

	/*
	 * Insertion when no call to "vcpu_update_boot" has been made yet.
	 * The "boot_list" is expected to be empty.
	 */
	EXPECT_TRUE(vm_init_next(1, &vm_cur, false, 0));
	vm_cur->boot_order = 3;
	vm_update_boot(vm_cur);
	expected_final_order.push_back(vm_cur);

	EXPECT_EQ(vm_get_boot_vm()->id, vm_cur->id);

	/* Insertion at the head of the boot list */
	EXPECT_TRUE(vm_init_next(1, &vm_cur, false, 0));
	vm_cur->boot_order = 1;
	vm_update_boot(vm_cur);
	expected_final_order.push_back(vm_cur);

	EXPECT_EQ(vm_get_boot_vm()->id, vm_cur->id);

	/* Insertion of two in the middle of the boot list */
	for (uint32_t i = 0; i < 2; i++) {
		EXPECT_TRUE(vm_init_next(MAX_CPUS, &vm_cur, false, 0));
		vm_cur->boot_order = 2;
		vm_update_boot(vm_cur);
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
	vm_update_boot(vm_cur);
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
	vm = vm_get_boot_vm();
	for (it = expected_final_order.begin();
	     it != expected_final_order.end(); it++) {
		EXPECT_TRUE(vm != NULL);
		EXPECT_EQ((*it)->id, vm->id);
		vm = vm_get_next_boot(vm);
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
			bitmaps[i]));

		/*
		 * Validate bind related operations. For this test considering
		 * only global notifications.
		 */
		vm_notifications_update_bindings(current_vm_locked, is_from_vm,
						 dummy_senders[i]->id,
						 bitmaps[i]);

		EXPECT_TRUE(vm_notifications_validate_binding(
			current_vm_locked, is_from_vm, dummy_senders[i]->id,
			bitmaps[i]));

		EXPECT_FALSE(vm_notifications_validate_binding(
			current_vm_locked, is_from_vm, dummy_senders[1 - i]->id,
			bitmaps[i]));

		EXPECT_FALSE(vm_notifications_validate_binding(
			current_vm_locked, is_from_vm, dummy_senders[i]->id,
			bitmaps[1 - i]));

		EXPECT_FALSE(vm_notifications_validate_binding(
			current_vm_locked, is_from_vm, dummy_senders[i]->id,
			bitmaps[2]));
	}

	/** Clean up bind for other tests. */
	vm_notifications_update_bindings(current_vm_locked, is_from_vm, 0,
					 bitmaps[0]);
	vm_notifications_update_bindings(current_vm_locked, is_from_vm, 0,
					 bitmaps[1]);

	vm_unlock(&current_vm_locked);
}

/**
 * Validates updates and check functions for binding notifications, namely the
 * configuration of bindings of global and per-vCPU notifications.
 */
TEST_F(vm, vm_notification_bind_global_only)
{
	struct_vm *current_vm;
	struct vm_locked current_vm_locked;
	struct_vm *dummy_sender;
	ffa_notifications_bitmap_t global = 0x00000000FFFFFFFFU;
	bool is_from_vm = true;

	CHECK(vm_get_count() >= 2);

	current_vm = vm_find_index(0);

	dummy_sender = vm_find_index(1);

	current_vm_locked = vm_lock(current_vm);

	vm_notifications_update_bindings(current_vm_locked, is_from_vm,
					 dummy_sender->id, global);

	/* Check validation of global notifications bindings. */
	EXPECT_TRUE(vm_notifications_validate_binding(
		current_vm_locked, is_from_vm, dummy_sender->id, global));

	/** Undo the binding */
	vm_notifications_update_bindings(current_vm_locked, is_from_vm, 0,
					 global);
	EXPECT_TRUE(vm_notifications_validate_binding(current_vm_locked,
						      is_from_vm, 0, global));

	vm_unlock(&current_vm_locked);
}

/**
 * Validates accesses to global notifications bitmaps.
 */
TEST_F(vm, vm_notifications_set_and_get)
{
	struct_vm *current_vm;
	struct vm_locked current_vm_locked;
	struct_vm *dummy_sender;
	ffa_notifications_bitmap_t global = 0x00000000FFFFFFFFU;
	ffa_notifications_bitmap_t ret;
	struct notifications *notifications;
	const bool is_from_vm = true;

	CHECK(vm_get_count() >= 2);

	current_vm = vm_find_index(0);
	dummy_sender = vm_find_index(1);

	notifications = &current_vm->notifications.from_vm;
	current_vm_locked = vm_lock(current_vm);

	vm_notifications_update_bindings(current_vm_locked, is_from_vm,
					 dummy_sender->id, global);

	/*
	 * Validate set/get for global notifications.
	 */
	vm_notifications_partition_set_pending(current_vm_locked, is_from_vm,
					       global);

	EXPECT_EQ(notifications->global.pending, global);

	/* Counter should track pending notifications. */
	EXPECT_FALSE(vm_is_notifications_pending_count_zero());

	ret = vm_notifications_partition_get_pending(current_vm_locked,
						     is_from_vm);
	EXPECT_EQ(ret, global);
	EXPECT_EQ(notifications->global.pending, 0ull);

	/*
	 * After getting the pending notifications, the pending count should
	 * be zeroed.
	 */
	EXPECT_TRUE(vm_is_notifications_pending_count_zero());

	/** Undo the binding */
	vm_notifications_update_bindings(current_vm_locked, is_from_vm, 0ull,
					 global);
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

		vm_notifications_partition_set_pending(current_vm_locked,
						       is_from_vm, to_set);

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
							     is_from_vm);
		EXPECT_EQ(got, to_set);

		EXPECT_EQ(notifications->global.info_get_retrieved, 0U);
		EXPECT_EQ(notifications->global.pending, 0U);

		vm_unlock(&current_vm_locked);
	}
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
					       FFA_NOTIFICATION_MASK(10));

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
						     is_from_vm);
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
 * Also checks that vCPUs with pending IPIs are only reported if the
 * vCPU is in the waiting state.
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
	struct_vm *current_vm = vm_find_index(4);
	struct vcpu *target_vcpu = vm_get_vcpu(current_vm, 1);
	struct vcpu_locked vcpu_locked;
	const bool is_from_vm = false;
	struct vm_locked current_vm_locked = vm_lock(current_vm);

	EXPECT_TRUE(current_vm->vcpu_count >= 2);

	vcpu_locked = vcpu_lock(target_vcpu);
	vcpu_virt_interrupt_inject(vcpu_locked, HF_IPI_INTID);
	vcpu_virt_interrupt_enable(vcpu_locked, HF_IPI_INTID, true);
	vcpu_unlock(&vcpu_locked);

	vm_notifications_info_get_pending(current_vm_locked, is_from_vm, ids,
					  &ids_count, lists_sizes, &lists_count,
					  FFA_NOTIFICATIONS_INFO_GET_MAX_IDS,
					  &current_state);

	EXPECT_EQ(ids_count, 0);
	EXPECT_EQ(lists_count, 0);

	target_vcpu->state = VCPU_STATE_WAITING;

	vm_notifications_info_get_pending(current_vm_locked, is_from_vm, ids,
					  &ids_count, lists_sizes, &lists_count,
					  FFA_NOTIFICATIONS_INFO_GET_MAX_IDS,
					  &current_state);

	EXPECT_EQ(ids_count, 2);
	EXPECT_EQ(lists_count, 1);
	EXPECT_EQ(lists_sizes[0], 1);
	EXPECT_EQ(ids[0], current_vm->id);
	EXPECT_EQ(ids[1], 1);
	EXPECT_EQ(target_vcpu->interrupts_info_get_retrieved, true);

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

	vcpu_locked = vcpu_lock(target_vcpu);

	EXPECT_EQ(vcpu_virt_interrupt_get_pending_and_enabled(vcpu_locked),
		  HF_IPI_INTID);
	EXPECT_FALSE(vcpu_locked.vcpu->interrupts_info_get_retrieved);

	vcpu_unlock(&vcpu_locked);

	vm_unlock(&current_vm_locked);
}

TEST_F(vm, pending_interrupts_info_retrieved)
{
	struct_vm *test_vm = vm_find_index(4);
	struct_vcpu *vcpu = vm_get_vcpu(test_vm, 1);
	const uint32_t intid = HF_NUM_INTIDS - 2;
	struct vm_locked test_vm_locked;
	struct vcpu_locked vcpu_locked;

	/*
	 *
	 * Following set of variables that are also expected to be used when
	 * handling ffa_notification_info_get.
	 * For this 'ids_count' has been initialized such that it indicates
	 * there is no space in the list for a per-vCPU notification (VM ID and
	 * VCPU ID).
	 */
	uint16_t ids[FFA_NOTIFICATIONS_INFO_GET_MAX_IDS] = {0};
	uint32_t ids_count = 0;
	uint32_t lists_sizes[FFA_NOTIFICATIONS_INFO_GET_MAX_IDS] = {0};
	uint32_t lists_count = 0;
	enum notifications_info_get_state current_state = INIT;

	/*
	 * Make it such the FF-A and vCPU ID are included in the list,
	 * when invoking notification info get.
	 */
	test_vm->sri_policy.intr_while_waiting = true;

	vcpu_locked = vcpu_lock(vcpu);

	/* Check this is starting from a clean state. */
	EXPECT_EQ(vcpu_virt_interrupt_count_get(vcpu_locked), 0);
	EXPECT_FALSE(vcpu->interrupts_info_get_retrieved);

	/* Enable and get pending. */
	vcpu_virt_interrupt_enable(vcpu_locked, intid, true);

	vcpu_virt_interrupt_inject(vcpu_locked, intid);

	vcpu->state = VCPU_STATE_WAITING;

	EXPECT_EQ(vcpu_virt_interrupt_count_get(vcpu_locked), 1);

	/* Free resource. */
	vcpu_unlock(&vcpu_locked);

	test_vm_locked = vm_lock(test_vm);

	vm_notifications_info_get_pending(test_vm_locked, true, ids, &ids_count,
					  lists_sizes, &lists_count,
					  FFA_NOTIFICATIONS_INFO_GET_MAX_IDS,
					  &current_state);

	/* Assert the information flag as been retrieved. */
	EXPECT_TRUE(vcpu->interrupts_info_get_retrieved);

	vm_unlock(&test_vm_locked);

	/*  Pop to clear test and attest intid is returned. */
	vcpu_locked = vcpu_lock(vcpu);

	EXPECT_EQ(vcpu_virt_interrupt_get_pending_and_enabled(vcpu_locked),
		  intid);

	EXPECT_FALSE(vcpu_locked.vcpu->interrupts_info_get_retrieved);

	vcpu_unlock(&vcpu_locked);
}
} /* namespace */
