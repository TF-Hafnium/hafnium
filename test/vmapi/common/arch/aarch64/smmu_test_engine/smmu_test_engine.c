/*
 * Copyright 2026 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "smmu_test_engine.h"

#include <stdint.h>

#include "hf/arch/barriers.h"
#include "hf/arch/cache.h"

#include "hf/addr.h"

#include <hf/mmio.h>

/**
 * This driver was adapted from the implementation in the tf-a tests repository
 * at tf-a-tests/spm/cactus/cactus_tests/cactus_tests_smmuv3.c.
 */

/* The test engine supports numerous frames but we only use a few */
#define FRAME_COUNT (2U)
#define FRAME_SIZE (0x80U) /* 128 bytes */
#define F_IDX(n) ((size_t)(n) * FRAME_SIZE)

/* Commands supported by SMMUv3TestEngine built into the AEM */
#define ENGINE_NO_FRAME (0U)
#define ENGINE_HALTED (1U)

/*
 * ENGINE_MEMCPY: Read and Write transactions
 * ENGINE_RAND48: Only Write transactions: Source address not required
 * ENGINE_SUM64: Only read transactions: Target address not required
 */
#define ENGINE_MEMCPY (2U)
#define ENGINE_RAND48 (3U)
#define ENGINE_SUM64 (4U)
#define ENGINE_ERROR (0xFFFFFFFFU)
#define ENGINE_MIS_CFG (ENGINE_ERROR - 1)

/*
 * Refer to:
 * https://developer.arm.com/documentation/100964/1111-00/Trace-components/SMMUv3TestEngine---trace
 */

/* Offset of various control fields belonging to User Frame */
#define CMD_OFF (0x0U)
#define UCTRL_OFF (0x4U)
#define ATTR_OFF (0x20U)
#define SEED_OFF (0x24U)
#define BEGIN_OFF (0x28U)
#define END_CTRL_OFF (0x30U)
#define STRIDE_OFF (0x38U)
#define UDATA_OFF (0x40U)

/* Offset of various control fields belonging to PRIV Frame */
#define PCTRL_OFF (0x0U)
#define DOWNSTREAM_PORT_OFF (0x4U)
#define STREAM_ID_OFF (0x8U)
#define SUBSTREAM_ID_OFF (0xCU)

/* Base addresses of the MMIO regions */
#define USR_BASE_FRAME (0x2B500000)
#define PRIV_BASE_FRAME (0x2B510000)

/* MISC */
#define LOOP_COUNT (5000U)
#define NO_SUBSTREAMID (0xFFFFFFFFU)

static bool run_testengine(uint32_t operation, uintptr_t source_addr,
			   uintptr_t target_addr, size_t transfer_size,
			   uint32_t attributes)
{
	const uint32_t streamID_list[] = {0U, 1U};
	uintptr_t begin_addr;
	uintptr_t end_addr;
	uintptr_t dest_addr;
	uint32_t status;
	uint32_t f;
	uint32_t attempts;
	/* NOLINTBEGIN(performance-no-int-to-ptr) */
	char *priv_base = (char *)PRIV_BASE_FRAME;
	char *usr_base = (char *)USR_BASE_FRAME;
	/* NOLINTEND(performance-no-int-to-ptr) */

	assert(operation == ENGINE_MEMCPY || operation == ENGINE_RAND48);

	for (f = 0U; f < FRAME_COUNT; f++) {
		begin_addr = source_addr + (transfer_size * f);
		end_addr = begin_addr + transfer_size - 1U;

		if (operation == ENGINE_MEMCPY) {
			dest_addr = target_addr + (transfer_size * f);
		} else {
			dest_addr = 0;
		}

		/* Initiate DMA sequence */
		mmio_write32_offset(priv_base + F_IDX(f), PCTRL_OFF, 0);
		mmio_write32_offset(priv_base + F_IDX(f), DOWNSTREAM_PORT_OFF,
				    0);
		mmio_write32_offset(priv_base + F_IDX(f), STREAM_ID_OFF,
				    streamID_list[f % 2]);
		mmio_write32_offset(priv_base + F_IDX(f), SUBSTREAM_ID_OFF,
				    NO_SUBSTREAMID);

		mmio_write32_offset(usr_base + F_IDX(f), UCTRL_OFF, 0);
		mmio_write32_offset(usr_base + F_IDX(f), ATTR_OFF, attributes);

		if (operation == ENGINE_RAND48) {
			mmio_write32_offset(usr_base + F_IDX(f), SEED_OFF,
					    (f + 1) * 42);
		}

		mmio_write64_offset(usr_base + F_IDX(f), BEGIN_OFF, begin_addr);
		mmio_write64_offset(usr_base + F_IDX(f), END_CTRL_OFF,
				    end_addr);

		/* Legal values for stride: 1 and any multiples of 8 */
		mmio_write64_offset(usr_base + F_IDX(f), STRIDE_OFF, 1);
		mmio_write64_offset(usr_base + F_IDX(f), UDATA_OFF, dest_addr);

		mmio_write32_offset(usr_base + F_IDX(f), CMD_OFF, operation);

		dlog_verbose(
			"SMMUv3TestEngine: waiting completion for frame: %u\n",
			f);

		/*
		 * It is guaranteed that a read of "cmd" fields after writing to
		 * it will immediately return ENGINE_FRAME_MISCONFIGURED if the
		 * command was invalid.
		 */
		if (mmio_read32_offset(usr_base + F_IDX(f), CMD_OFF) ==
		    ENGINE_MIS_CFG) {
			dlog_error(
				"SMMUv3TestEngine: misconfigured for frame: "
				"%u\n",
				f);
			return false;
		}

		/* Wait for operation to be complete */
		attempts = 0U;
		while (attempts < LOOP_COUNT) {
			status = mmio_read32_offset(usr_base + F_IDX(f),
						    CMD_OFF);
			if (status == ENGINE_HALTED) {
				break;
			}

			if (status == ENGINE_ERROR) {
				dlog_error(
					"SMMUv3: test failed, engine error.\n");
				return false;
			}

			/*
			 * TODO: Introduce a small delay here to make sure the
			 * CPU memory accesses do not starve the interconnect
			 * due to continuous polling.
			 */
			attempts++;
		}

		if (attempts == LOOP_COUNT) {
			dlog_error(
				"SMMUv3: test failed, exceeded max. wait "
				"loop.\n");
			return false;
		}

		data_sync_barrier();
	}

	return true;
}

bool run_smmuv3_memcpy(uintptr_t start_address, size_t size,
		       uint32_t attributes)
{
	uintptr_t target_address;
	size_t cpy_range = size >> 1;
	bool ret;

	/*
	 * The test engine's MEMCPY command copies data from the region in
	 * range [begin, end_incl] to the region with base address as udata.
	 * In this test, we configure the test engine to initiate memcpy from
	 * scratch page located at MEMCPY_SOURCE_BASE to the page located at
	 * address MEMCPY_TARGET_BASE
	 */

	target_address = start_address + cpy_range;
	ret = run_testengine(ENGINE_MEMCPY, start_address, target_address,
			     cpy_range / FRAME_COUNT, attributes);

	if (ret) {
		/*
		 * Invalidate cached entries to force the CPU to fetch the data
		 * from Main memory
		 */
		arch_cache_data_invalidate_range(va_init(start_address),
						 cpy_range);
		arch_cache_data_invalidate_range(va_init(target_address),
						 cpy_range);

		/* Compare source and destination memory locations for data */
		for (size_t i = 0U; i < (cpy_range / 8U); i++) {
			/* NOLINTBEGIN(performance-no-int-to-ptr) */
			if (mmio_read64((char *)start_address + 8 * i) !=
			    mmio_read64((char *)target_address + 8 * i)) {
				dlog_error("SMMUv3: Mem copy failed: %lx\n",
					   target_address + 8 * i);
				return false;
			}
			/* NOLINTEND(performance-no-int-to-ptr) */
		}
	}

	return ret;
}

bool run_smmuv3_rand48(uintptr_t start_address, size_t size,
		       uint32_t attributes)
{
	return run_testengine(ENGINE_RAND48, start_address, 0,
			      size / FRAME_COUNT, attributes);
}
