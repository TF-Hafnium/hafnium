/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

/* Define the standard types for the platform. */
#if defined(__linux__) && defined(__KERNEL__)

#include <linux/types.h>

#define INT32_C(c) c

typedef phys_addr_t hf_ipaddr_t;

#else

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "hf/arch/vmid_base.h"

typedef uintptr_t hf_ipaddr_t;

#endif

#define HF_INVALID_VM_ID 0x7fff

/**
 * The bit of the VM ID which indicates whether the VM ID is allocated by the
 * normal world or the secure world.
 */
#define HF_VM_ID_WORLD_MASK 0x8000

/** The special VM ID reserved for the hypervisor in the normal world. */
#define HF_HYPERVISOR_VM_ID 0

/**
 * An offset to use when assigning VM IDs within the current world.
 * The offset from HF_VM_ID_BASE is needed because VM ID `HF_VM_ID_BASE + 0` is
 * reserved for the hypervisor/SPM.
 */
#define HF_VM_ID_OFFSET (HF_VM_ID_BASE + 1)

/** The index of the primary VM, if it exists in this world. */
#define HF_PRIMARY_VM_INDEX 0

/**
 * The special VM ID reserved for the OS or SPMC running in the trusted
 * execution environment, e.g. secure EL1 or EL2 on AArch64.
 */
#define HF_TEE_VM_ID 0x8000

/** Sleep value for an indefinite period of time. */
#define HF_SLEEP_INDEFINITE 0xffffffffffffffff

/** The amount of data that can be sent to a mailbox. */
#define HF_MAILBOX_SIZE 4096

/** The number of virtual interrupt IDs which are supported. */
#define HF_NUM_INTIDS 64

/** Interrupt ID returned when there is no interrupt pending. */
#define HF_INVALID_INTID 0xffffffff

/** Interrupt ID indicating the mailbox is readable. */
#define HF_MAILBOX_READABLE_INTID 1

/** Interrupt ID indicating a mailbox is writable. */
#define HF_MAILBOX_WRITABLE_INTID 2

/** The virtual interrupt ID used for the virtual timer. */
#define HF_VIRTUAL_TIMER_INTID 3
