/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include "hf/vm.h"

void ffa_vm_disable_interrupts(struct vm_locked vm_locked);

void ffa_vm_init(struct mpool *ppool);

struct vm_locked ffa_vm_nwd_alloc(ffa_id_t vm_id);

bool ffa_vm_supports_indirect_messages(struct vm *vm);

bool ffa_vm_notifications_info_get(uint16_t *ids, uint32_t *ids_count,
				   uint32_t *lists_sizes, uint32_t *lists_count,
				   uint32_t ids_count_max);

/** Get NWd VM's structure. */
struct vm_locked ffa_vm_find_locked(ffa_id_t vm_id);

struct vm_locked ffa_vm_find_locked_create(ffa_id_t vm_id);

void ffa_vm_nwd_free(struct vm_locked to_destroy_locked);

/** Reclaim all resources belonging to VM in aborted state. */
void ffa_vm_free_resources(struct vm_locked vm_locked, struct mpool *ppool);

/** Checks whether managed exit is supported by given SP. */
bool ffa_vm_managed_exit_supported(struct vm *vm);

/**
 * Traverses the nwd vms and determines if the RX/TX buffers
 * are mapped, if so, updates the provided amd descriptor.
 */
bool ffa_get_nwd_rxtx_buffer_info(struct ffa_address_map_desc *amd,
				  bool check_rx_buffer, bool *buffer_mapped,
				  uint16_t *curr_index, ffa_id_t *nwd_id);
