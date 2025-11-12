/*
 * Copyright 2026 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/call.h"
#include "hf/check.h"

#include "smmu_test_engine.h"
#include "test/hftest.h"

TEST_SERVICE(smmu_test_engine_static_secure)
{
	/* Map SMMUv3TestEngine device */
	struct hftest_context *ctx = hftest_get_context();
	hftest_map_device_regions(ctx);
	struct ffa_partition_manifest *manifest = &ctx->partition_manifest;
	struct memory_region *mem_region;

	EXPECT_GE(manifest->mem_region_count, 1);
	mem_region = &manifest->mem_regions[0];
	EXPECT_STREQ(mem_region->description.data, "test-dma-memory-secure");
	EXPECT_EQ(mem_region->base_address, 0x7300000);
	EXPECT_EQ(mem_region->is_relative, false);
	EXPECT_EQ(mem_region->page_count, 0x8);
	EXPECT_EQ(mem_region->attributes, 0x3);
	EXPECT_EQ(mem_region->dma_prop.smmu_id, 0x0);
	EXPECT_EQ(mem_region->dma_access_permissions, 0x3);
	EXPECT_EQ(mem_region->dma_prop.stream_count, 0x2);
	EXPECT_EQ(mem_region->dma_prop.stream_ids[0], 0x0);
	EXPECT_EQ(mem_region->dma_prop.stream_ids[1], 0x1);

	EXPECT_TRUE(run_smmuv3_rand48(mem_region->base_address,
				      mem_region->page_count * FFA_PAGE_SIZE,
				      DMA_ENGINE_ATTR_DEST_ACACHE_RAWAWB_S));
	ffa_yield();
}
