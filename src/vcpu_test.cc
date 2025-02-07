/*
 * Copyright 2025 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include <gmock/gmock.h>

extern "C" {
#include "hf/arch/mm.h"

#include "hf/check.h"
#include "hf/vcpu.h"
#include "hf/vm.h"
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

constexpr size_t TEST_HEAP_SIZE = PAGE_SIZE * 64;
const int TOP_LEVEL = arch_mm_stage2_max_level();
class vcpu : public ::testing::Test
{
       protected:
	static std::unique_ptr<uint8_t[]> test_heap;
	struct mpool ppool;
	const uint32_t first_intid = HF_NUM_INTIDS - 2;
	const uint32_t second_intid = HF_NUM_INTIDS - 1;
	struct_vm *test_vm;
	struct_vcpu *test_vcpu;
	struct vcpu_locked vcpu_locked;
	struct interrupts *interrupts;

	void SetUp() override
	{
		if (!test_heap) {
			test_heap = std::make_unique<uint8_t[]>(TEST_HEAP_SIZE);
			mpool_init(&ppool, sizeof(struct mm_page_table));
			mpool_add_chunk(&ppool, test_heap.get(),
					TEST_HEAP_SIZE);
		}

		test_vm = vm_init(HF_VM_ID_OFFSET, 8, &ppool, false, 0);
		test_vcpu = vm_get_vcpu(test_vm, 0);
		vcpu_locked = vcpu_lock(test_vcpu);
		interrupts = &test_vcpu->interrupts;

		/* Enable the interrupts used in testing. */
		vcpu_virt_interrupt_enable(vcpu_locked, first_intid, true);
		vcpu_virt_interrupt_enable(vcpu_locked, second_intid, true);
	}

	void TearDown() override
	{
		vcpu_unlock(&vcpu_locked);
	}
};

std::unique_ptr<uint8_t[]> vcpu::test_heap;

/**
 * Check that interrupts that are set pending, can later be fetched
 * from the queue.
 */
TEST_F(vcpu, pending_interrupts_are_fetched)
{
	EXPECT_EQ(vcpu_virt_interrupt_count_get(vcpu_locked), 0);

	/* Pend the interrupts, and check the count is incremented. */
	vcpu_virt_interrupt_inject(vcpu_locked, first_intid);
	vcpu_virt_interrupt_inject(vcpu_locked, second_intid);
	EXPECT_EQ(vcpu_virt_interrupt_count_get(vcpu_locked), 2);

	/*
	 * Check the pended interrupts are correctly returned, and once both
	 * have been returned the invalid intid is given to show there are no
	 * more pending interrupts.
	 */
	EXPECT_EQ(vcpu_virt_interrupt_get_pending_and_enabled(vcpu_locked),
		  first_intid);
	EXPECT_EQ(vcpu_virt_interrupt_get_pending_and_enabled(vcpu_locked),
		  second_intid);
	EXPECT_EQ(vcpu_virt_interrupt_get_pending_and_enabled(vcpu_locked),
		  HF_INVALID_INTID);

	/*
	 * Check, having been fetched, the interrupts are no longer marked as
	 * pending in the bitmap, and the interrupt count is 0.
	 */
	EXPECT_FALSE(vcpu_is_virt_interrupt_pending(interrupts, first_intid));
	EXPECT_FALSE(vcpu_is_virt_interrupt_pending(interrupts, second_intid));
	EXPECT_EQ(vcpu_virt_interrupt_count_get(vcpu_locked), 0);

	/*
	 * Check that this expected behavour happens on a consecutive run.
	 * Invert the order of the interrupts to add some variation.
	 */
	vcpu_virt_interrupt_inject(vcpu_locked, second_intid);
	vcpu_virt_interrupt_inject(vcpu_locked, first_intid);

	EXPECT_TRUE(vcpu_is_virt_interrupt_pending(interrupts, second_intid));
	EXPECT_TRUE(vcpu_is_virt_interrupt_pending(interrupts, first_intid));
	EXPECT_EQ(vcpu_virt_interrupt_irq_count_get(vcpu_locked), 2);

	EXPECT_EQ(vcpu_virt_interrupt_get_pending_and_enabled(vcpu_locked),
		  second_intid);
	EXPECT_EQ(vcpu_virt_interrupt_get_pending_and_enabled(vcpu_locked),
		  first_intid);
	EXPECT_EQ(vcpu_virt_interrupt_get_pending_and_enabled(vcpu_locked),
		  HF_INVALID_INTID);

	EXPECT_FALSE(vcpu_is_virt_interrupt_pending(interrupts, second_intid));
	EXPECT_FALSE(vcpu_is_virt_interrupt_pending(interrupts, first_intid));
	EXPECT_EQ(vcpu_virt_interrupt_irq_count_get(vcpu_locked), 0);
}

/*
 * Check that a disabled interrupt will not be returned until it is
 * enabled.
 */
TEST_F(vcpu, pending_interrupts_not_enabled_are_not_returned)
{
	/*
	 * Pend the interrupts, check the count is incremented, the pending
	 * interrupts are returned correctly and this causes the count to
	 * return to 0.
	 */
	vcpu_virt_interrupt_inject(vcpu_locked, first_intid);
	vcpu_virt_interrupt_inject(vcpu_locked, second_intid);
	EXPECT_EQ(vcpu_virt_interrupt_count_get(vcpu_locked), 2);
	EXPECT_EQ(vcpu_virt_interrupt_get_pending_and_enabled(vcpu_locked),
		  first_intid);
	EXPECT_EQ(vcpu_virt_interrupt_get_pending_and_enabled(vcpu_locked),
		  second_intid);
	EXPECT_EQ(vcpu_virt_interrupt_count_get(vcpu_locked), 0);

	/* Again pend the interrupts. */
	vcpu_virt_interrupt_inject(vcpu_locked, first_intid);
	vcpu_virt_interrupt_inject(vcpu_locked, second_intid);
	EXPECT_EQ(vcpu_virt_interrupt_count_get(vcpu_locked), 2);

	/* Disable the first interrupt. */
	vcpu_virt_interrupt_enable(vcpu_locked, first_intid, false);
	EXPECT_EQ(vcpu_virt_interrupt_count_get(vcpu_locked), 1);

	/*
	 * Check that the disabled first interrupt is not returned,
	 * the second intid should be returned and then the invalid
	 * intid to show there are no more pending and enabled interrupts.
	 */
	EXPECT_EQ(vcpu_virt_interrupt_get_pending_and_enabled(vcpu_locked),
		  second_intid);
	EXPECT_EQ(vcpu_virt_interrupt_get_pending_and_enabled(vcpu_locked),
		  HF_INVALID_INTID);
	EXPECT_EQ(vcpu_virt_interrupt_count_get(vcpu_locked), 0);

	/* Reenable the first interrupt and disable the second interrupt.*/
	vcpu_virt_interrupt_enable(vcpu_locked, first_intid, true);
	vcpu_virt_interrupt_enable(vcpu_locked, second_intid, false);
	EXPECT_EQ(vcpu_virt_interrupt_count_get(vcpu_locked), 1);

	/*
	 * Check that an interrupt injected when the interrupt is disabled will
	 * eventually be returned once the interrupt is enabled.
	 */
	vcpu_virt_interrupt_inject(vcpu_locked, second_intid);
	EXPECT_EQ(vcpu_virt_interrupt_count_get(vcpu_locked), 1);

	/*
	 * Check that it is now returned as a pending interrupt and is the only
	 * interrupt pending.
	 */
	EXPECT_EQ(vcpu_virt_interrupt_get_pending_and_enabled(vcpu_locked),
		  first_intid);
	EXPECT_EQ(vcpu_virt_interrupt_get_pending_and_enabled(vcpu_locked),
		  HF_INVALID_INTID);
	EXPECT_EQ(vcpu_virt_interrupt_count_get(vcpu_locked), 0);

	/* Enable the second interrupt to check it will now be returned. */
	vcpu_virt_interrupt_enable(vcpu_locked, second_intid, true);
	EXPECT_EQ(vcpu_virt_interrupt_count_get(vcpu_locked), 1);

	/*
	 * Check that it is now returned as a pending interrupt and is the only
	 * interrupt pending.
	 */
	EXPECT_EQ(vcpu_virt_interrupt_get_pending_and_enabled(vcpu_locked),
		  second_intid);
	EXPECT_EQ(vcpu_virt_interrupt_get_pending_and_enabled(vcpu_locked),
		  HF_INVALID_INTID);
	EXPECT_EQ(vcpu_virt_interrupt_count_get(vcpu_locked), 0);
}

/**
 * Check the queue state from disabling some interrupts. And then reenabling.
 */
TEST_F(vcpu, injecting_getting_interrupts_multiple_times)
{
	EXPECT_EQ(vcpu_virt_interrupt_count_get(vcpu_locked), 0);

	/* Pend the interrupts, and check the count is incremented. */
	vcpu_virt_interrupt_inject(vcpu_locked, first_intid);
	vcpu_virt_interrupt_inject(vcpu_locked, second_intid);

	for (uint32_t i = 0; i < VINT_QUEUE_MAX * 3; i++) {
		uint32_t it_intid = vcpu_virt_interrupt_get_pending_and_enabled(
			vcpu_locked);
		uint32_t peek_intid =
			vcpu_virt_interrupt_peek_pending_and_enabled(
				vcpu_locked);

		EXPECT_NE(it_intid, HF_INVALID_INTID);
		/*
		 * Sequence to validate the `first_intid` and `second_intid`
		 * are retrieved and left pending as expected.
		 */
		if (i % 2 == 0) {
			EXPECT_EQ(it_intid, first_intid);
			EXPECT_EQ(peek_intid, second_intid);
		} else {
			EXPECT_EQ(it_intid, second_intid);
			EXPECT_EQ(peek_intid, first_intid);
		}
		EXPECT_EQ(vcpu_virt_interrupt_count_get(vcpu_locked), 1);
		vcpu_virt_interrupt_inject(vcpu_locked, it_intid);
		EXPECT_EQ(vcpu_virt_interrupt_count_get(vcpu_locked), 2);
	}

	EXPECT_NE(vcpu_virt_interrupt_get_pending_and_enabled(vcpu_locked),
		  HF_INVALID_INTID);
	EXPECT_EQ(vcpu_virt_interrupt_count_get(vcpu_locked), 1);
	EXPECT_NE(vcpu_virt_interrupt_get_pending_and_enabled(vcpu_locked),
		  HF_INVALID_INTID);
	EXPECT_EQ(vcpu_virt_interrupt_count_get(vcpu_locked), 0);
}

/*
 * Test that each interrupt ID is only set to pending and the count is
 * incremented once.
 */
TEST_F(vcpu, pending_interrupt_is_only_added_once)
{
	EXPECT_EQ(vcpu_virt_interrupt_count_get(vcpu_locked), 0);

	/* Pend the interrupt, and check the count is incremented. */
	vcpu_virt_interrupt_inject(vcpu_locked, first_intid);
	EXPECT_EQ(vcpu_virt_interrupt_count_get(vcpu_locked), 1);

	/* Inject the same interrupt the count should not be incremented. */
	vcpu_virt_interrupt_inject(vcpu_locked, first_intid);
	EXPECT_EQ(vcpu_virt_interrupt_count_get(vcpu_locked), 1);

	EXPECT_EQ(vcpu_virt_interrupt_get_pending_and_enabled(vcpu_locked),
		  first_intid);
	EXPECT_EQ(vcpu_virt_interrupt_get_pending_and_enabled(vcpu_locked),
		  HF_INVALID_INTID);
	EXPECT_EQ(vcpu_virt_interrupt_count_get(vcpu_locked), 0);
}

/* Check that an cleared interrupts are made to be no longer pending. */
TEST_F(vcpu, pending_interrupts_can_be_cleared)
{
	/*
	 * Pend the interrupts, check the count is incremented, the pending
	 * interrupts are returned correctly and this causes the count to
	 * return to 0.
	 */
	vcpu_virt_interrupt_inject(vcpu_locked, first_intid);
	vcpu_virt_interrupt_inject(vcpu_locked, second_intid);
	EXPECT_EQ(vcpu_virt_interrupt_count_get(vcpu_locked), 2);
	EXPECT_EQ(vcpu_virt_interrupt_get_pending_and_enabled(vcpu_locked),
		  first_intid);
	EXPECT_EQ(vcpu_virt_interrupt_get_pending_and_enabled(vcpu_locked),
		  second_intid);
	EXPECT_EQ(vcpu_virt_interrupt_count_get(vcpu_locked), 0);

	/* Again pend the interrupts. */
	vcpu_virt_interrupt_inject(vcpu_locked, first_intid);
	vcpu_virt_interrupt_inject(vcpu_locked, second_intid);

	/* Remove the first interrupt. */
	vcpu_virt_interrupt_clear(vcpu_locked, first_intid);
	EXPECT_EQ(vcpu_virt_interrupt_count_get(vcpu_locked), 1);

	/*
	 * Check that the first interrupt is cleared.
	 * The second intid should be returned and then the invalid
	 * intid to show there are no more pending and enabled interrupts.
	 */
	EXPECT_EQ(vcpu_virt_interrupt_get_pending_and_enabled(vcpu_locked),
		  second_intid);
	EXPECT_EQ(vcpu_virt_interrupt_get_pending_and_enabled(vcpu_locked),
		  HF_INVALID_INTID);
	EXPECT_EQ(vcpu_virt_interrupt_count_get(vcpu_locked), 0);

	/* Inject the interrupts again. */
	vcpu_virt_interrupt_inject(vcpu_locked, first_intid);
	vcpu_virt_interrupt_inject(vcpu_locked, second_intid);
	EXPECT_EQ(vcpu_virt_interrupt_count_get(vcpu_locked), 2);

	/* Remove the second interrupt. */
	vcpu_virt_interrupt_clear(vcpu_locked, second_intid);
	EXPECT_EQ(vcpu_virt_interrupt_count_get(vcpu_locked), 1);

	/*
	 * Check that it is now returned as a pending interrupt and is the only
	 * interrupt pending.
	 */
	EXPECT_EQ(vcpu_virt_interrupt_get_pending_and_enabled(vcpu_locked),
		  first_intid);
	EXPECT_EQ(vcpu_virt_interrupt_get_pending_and_enabled(vcpu_locked),
		  HF_INVALID_INTID);
	EXPECT_EQ(vcpu_virt_interrupt_count_get(vcpu_locked), 0);
}

/*
 * Check that when an interrupt is cleared space is create for a new
 * interrupt to be injected. In addition that after clearing interrupts
 * the FIFO policy of the remaining interrupts is maintainted.
 */
TEST_F(vcpu, pending_interrupts_clear_full_list)
{
	/* Fill the interrupt queue for the vCPU. */
	for (int i = 0; i < VINT_QUEUE_MAX; i++) {
		vcpu_virt_interrupt_enable(vcpu_locked, i, true);
		vcpu_virt_interrupt_inject(vcpu_locked, i);
	}

	EXPECT_EQ(vcpu_virt_interrupt_count_get(vcpu_locked), VINT_QUEUE_MAX);

	/* Check clearing an interrupt clears space for another interrupt. */
	vcpu_virt_interrupt_clear(vcpu_locked, 2);

	vcpu_virt_interrupt_enable(vcpu_locked, VINT_QUEUE_MAX, true);
	vcpu_virt_interrupt_inject(vcpu_locked, VINT_QUEUE_MAX);

	/* Check disabled interrupts are also cleared. */
	vcpu_virt_interrupt_enable(vcpu_locked, 1, false);
	vcpu_virt_interrupt_clear(vcpu_locked, 1);

	vcpu_virt_interrupt_inject(vcpu_locked, VINT_QUEUE_MAX + 1);
	/*
	 * Enable the interrupt after injecting it to ensure it will be returned
	 * by vcpu_virt_interrupt_get_pending_and_enabled but is correctly
	 * injected when disabled.
	 */
	vcpu_virt_interrupt_enable(vcpu_locked, VINT_QUEUE_MAX + 1, true);

	/* Get the interrupts to check the FIFO order is maintained. */
	EXPECT_EQ(vcpu_virt_interrupt_get_pending_and_enabled(vcpu_locked), 0);
	EXPECT_EQ(vcpu_virt_interrupt_get_pending_and_enabled(vcpu_locked), 3);
	EXPECT_EQ(vcpu_virt_interrupt_get_pending_and_enabled(vcpu_locked), 4);
	EXPECT_EQ(vcpu_virt_interrupt_get_pending_and_enabled(vcpu_locked), 5);
	EXPECT_EQ(vcpu_virt_interrupt_get_pending_and_enabled(vcpu_locked), 6);
}
} /* namespace */
