/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include <gmock/gmock.h>

extern "C" {
#include "hf/mpool.h"
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

constexpr size_t TEST_HEAP_SIZE = PAGE_SIZE * 32;
const int TOP_LEVEL = arch_mm_stage2_max_level();

class vm : public ::testing::Test
{
	void SetUp() override
	{
		/*
		 * TODO: replace with direct use of stdlib allocator so
		 * sanitizers are more effective.
		 */
		test_heap = std::make_unique<uint8_t[]>(TEST_HEAP_SIZE);
		mpool_init(&ppool, sizeof(struct mm_page_table));
		mpool_add_chunk(&ppool, test_heap.get(), TEST_HEAP_SIZE);
	}

	std::unique_ptr<uint8_t[]> test_heap;

       protected:
	struct mpool ppool;

       public:
	static bool BootOrderBiggerThan(struct_vm *vm1, struct_vm *vm2)
	{
		return vm1->boot_order > vm2->boot_order;
	}
};

/**
 * If nothing is mapped, unmapping the hypervisor has no effect.
 */
TEST_F(vm, vm_unmap_hypervisor_not_mapped)
{
	struct_vm *vm;
	struct vm_locked vm_locked;

	EXPECT_TRUE(vm_init_next(1, &ppool, &vm, false));
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
	std::list<struct_vm *> expected_final_order;

	EXPECT_FALSE(vm_get_first_boot());

	/*
	 * Insertion when no call to "vm_update_boot" has been made yet.
	 * The "boot_list" is expected to be empty.
	 */
	EXPECT_TRUE(vm_init_next(1, &ppool, &vm_cur, false));
	vm_cur->boot_order = 1;
	vm_update_boot(vm_cur);
	expected_final_order.push_back(vm_cur);

	EXPECT_EQ(vm_get_first_boot()->id, vm_cur->id);

	/* Insertion at the head of the boot list */
	EXPECT_TRUE(vm_init_next(1, &ppool, &vm_cur, false));
	vm_cur->boot_order = 3;
	vm_update_boot(vm_cur);
	expected_final_order.push_back(vm_cur);

	EXPECT_EQ(vm_get_first_boot()->id, vm_cur->id);

	/* Insertion of two in the middle of the boot list */
	for (int i = 0; i < 2; i++) {
		EXPECT_TRUE(vm_init_next(1, &ppool, &vm_cur, false));
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

	/* Sort "expected_final_order" by "boot_order" field */
	expected_final_order.sort(vm::BootOrderBiggerThan);

	std::list<struct_vm *>::iterator it;
	for (it = expected_final_order.begin(), vm_cur = vm_get_first_boot();
	     it != expected_final_order.end() && vm_cur != NULL;
	     it++, vm_cur = vm_cur->next_boot) {
		EXPECT_EQ((*it)->id, vm_cur->id);
	}
}
} /* namespace */
