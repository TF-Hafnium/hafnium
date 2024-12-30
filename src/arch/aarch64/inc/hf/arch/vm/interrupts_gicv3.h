/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "hf/io.h"

#if GIC_VERSION != 3 && GIC_VERSION != 4
#error This header should only be included for GICv3 or v4.
#endif

/* Keep macro alignment */
/* clang-format off */

#define GIC_PRI_MASK 0xff

#define GICD_CTLR       IO32_C(GICD_BASE + 0x0000)
#define GICD_ISENABLER  IO32_ARRAY_C(GICD_BASE + 0x0100, 32)
#define GICD_ICENABLER  IO32_ARRAY_C(GICD_BASE + 0x0180, 32)
#define GICD_ISPENDR    IO32_ARRAY_C(GICD_BASE + 0x0200, 32)
#define GICD_ICPENDR    IO32_ARRAY_C(GICD_BASE + 0x0280, 32)
#define GICD_ISACTIVER  IO32_ARRAY_C(GICD_BASE + 0x0300, 32)
#define GICD_ICACTIVER  IO32_ARRAY_C(GICD_BASE + 0x0380, 32)
#define GICD_IPRIORITYR IO8_ARRAY_C(GICD_BASE + 0x0400, 1020)
#define GICD_ITARGETSR  IO8_ARRAY_C(GICD_BASE + 0x0800, 1020)
#define GICD_ICFGR      IO32_ARRAY_C(GICD_BASE + 0x0c00, 64)

#define SGI_BASE (0x10000)

#define GICR_WAKER      (0x0014)
#define GICR_IGROUPR0   (SGI_BASE + 0x0080)
#define GICR_ISENABLER0 (SGI_BASE + 0x0100)
#define GICR_ICENABLER0 (SGI_BASE + 0x0180)
#define GICR_ISPENDR0   (SGI_BASE + 0x0200)
#define GICR_ICPENDR0   (SGI_BASE + 0x0280)
#define GICR_ISACTIVER0 (SGI_BASE + 0x0300)
#define GICR_IPRIORITYR (SGI_BASE + 0x0400)
#define GICR_ICFGR      (SGI_BASE + 0x0c00)

/* PPIs INTIDs 16-31 */
#define MAX_PPI_ID (31)

/* clang-format on */

uint64_t interrupt_get_gic_rdist_addr(void);

void interrupt_gic_setup(void);
void interrupt_enable(uint32_t intid, bool enable);
void interrupt_enable_all(bool enable);
void interrupt_set_priority_mask(uint8_t min_priority);
void interrupt_set_priority(uint32_t intid, uint8_t priority);
void interrupt_set_edge_triggered(uint32_t intid, bool edge_triggered);
void interrupt_send_sgi(uint8_t intid, bool irm, uint8_t affinity3,
			uint8_t affinity2, uint8_t affinity1,
			uint16_t target_list);
uint32_t interrupt_get_and_acknowledge(void);
void interrupt_end(uint32_t intid);
