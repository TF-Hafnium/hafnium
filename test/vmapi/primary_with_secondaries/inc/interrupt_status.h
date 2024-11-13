/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "test/vmapi/ffa.h"

#define INTR_RESET 0x494E5452 /* ASCII representation of INTR */
#define INTR_PROGRAMMED (INTR_RESET + 1)
#define INTR_SERVICED (INTR_PROGRAMMED + 1)

void hftest_interrupt_status_set(uint32_t status);

uint32_t hftest_interrupt_status_get(void);

uint64_t hftest_setup_interrupt_status_page(void *recv_buf, void *send_buf);

void hftest_interrupt_status_page_setup(void *recv_buf, void *send_buf);

void hftest_interrupt_status_share_page_and_init(uint64_t page,
						 ffa_id_t receivers_ids[],
						 size_t receivers_count,
						 void *send_buf);
