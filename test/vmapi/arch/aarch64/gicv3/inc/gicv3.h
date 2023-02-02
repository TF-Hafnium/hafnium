/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/addr.h"
#include "hf/mm.h"
#include "hf/types.h"

#define PPI_IRQ_BASE 16
#define PHYSICAL_TIMER_IRQ (PPI_IRQ_BASE + 14)
#define VIRTUAL_TIMER_IRQ (PPI_IRQ_BASE + 11)
#define HYPERVISOR_TIMER_IRQ (PPI_IRQ_BASE + 10)

#define NANOS_PER_UNIT 1000000000

#define SERVICE_VM1 (HF_VM_ID_OFFSET + 1)

extern alignas(PAGE_SIZE) uint8_t send_page[PAGE_SIZE];
extern alignas(PAGE_SIZE) uint8_t recv_page[PAGE_SIZE];

extern hf_ipaddr_t send_page_addr;
extern hf_ipaddr_t recv_page_addr;

extern void *send_buffer;
extern void *recv_buffer;

extern volatile uint32_t last_interrupt_id;

void gicv3_system_setup(void);
