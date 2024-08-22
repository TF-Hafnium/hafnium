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

typedef phys_addr_t hf_ipaddr_t;

#endif

#if defined(__ASSEMBLER__) || (defined(__linux__) && defined(__KERNEL__))

#define INT32_C(c) c
#define UINT32_C(c) c##U
#define UINT64_C(c) c##ULL

#else

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "hf/arch/vmid_base.h"

#include "hf/vm_ids.h"

typedef uintptr_t hf_ipaddr_t;

#endif

/** Sleep value for an indefinite period of time. */
#define HF_SLEEP_INDEFINITE 0xffffffffffffffff

/** The amount of data that can be sent to a mailbox. */
#define HF_MAILBOX_SIZE ((size_t)4096)

/** Interrupt ID returned when there is no interrupt pending. */
#define HF_INVALID_INTID UINT32_C(0xffffffff)

/** Interrupt ID indicating the mailbox is readable. */
#define HF_MAILBOX_READABLE_INTID 1

/** Interrupt ID indicating a mailbox is writable. */
#define HF_MAILBOX_WRITABLE_INTID 2

/** The virtual interrupt ID used for the virtual timer. */
#define HF_VIRTUAL_TIMER_INTID 3

/** The virtual interrupt ID used for managed exit. */
#define HF_MANAGED_EXIT_INTID 4

/** The virtual interrupt ID used for notification pending interrupt. */
#define HF_NOTIFICATION_PENDING_INTID 5

/**
 * The interrupt ID (for both physical and virtual) used for
 * the inter-processor interrupt.
 */
#define HF_IPI_INTID 9

/** The physical interrupt ID use for the schedule receiver interrupt. */
#define HF_SCHEDULE_RECEIVER_INTID 8
