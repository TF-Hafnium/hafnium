/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include "hf/spci.h"
#include "hf/types.h"

/* Keep macro alignment */
/* clang-format off */

/* TODO: Define constants below according to spec. */
#define HF_VM_GET_COUNT                0xff01
#define HF_VCPU_GET_COUNT              0xff02
#define HF_VM_CONFIGURE                0xff03
#define HF_MAILBOX_CLEAR               0xff04
#define HF_MAILBOX_WRITABLE_GET        0xff05
#define HF_MAILBOX_WAITER_GET          0xff06
#define HF_INTERRUPT_ENABLE            0xff07
#define HF_INTERRUPT_GET               0xff08
#define HF_INTERRUPT_INJECT            0xff09
#define HF_SHARE_MEMORY                0xff0a

/* Custom SPCI-like calls returned from SPCI_RUN. */
#define HF_SPCI_RUN_WAIT_FOR_INTERRUPT 0xff0b
#define HF_SPCI_RUN_WAKE_UP            0xff0c

/* This matches what Trusty and its ATF module currently use. */
#define HF_DEBUG_LOG            0xbd000000

/* clang-format on */

enum hf_vcpu_run_code {
	/**
	 * The vCPU has been preempted but still has work to do. If the
	 * scheduling quantum has not expired, the scheduler MUST call
	 * `hf_vcpu_run` on the vCPU to allow it to continue.
	 */
	HF_VCPU_RUN_PREEMPTED = 0,

	/**
	 * The vCPU has voluntarily yielded the CPU. The scheduler SHOULD take a
	 * scheduling decision to give cycles to those that need them but MUST
	 * call `hf_vcpu_run` on the vCPU at a later point.
	 */
	HF_VCPU_RUN_YIELD = 1,

	/**
	 * The vCPU is blocked waiting for an interrupt. The scheduler MUST take
	 * it off the run queue and not call `hf_vcpu_run` on the vCPU until it
	 * has injected an interrupt, received `HF_VCPU_RUN_WAKE_UP` for it
	 * from another vCPU or the timeout provided in
	 * `hf_vcpu_run_return.sleep` is not `HF_SLEEP_INDEFINITE` and the
	 * specified duration has expired.
	 */
	HF_VCPU_RUN_WAIT_FOR_INTERRUPT = 2,

	/**
	 * The vCPU is blocked waiting for a message. The scheduler MUST take it
	 * off the run queue and not call `hf_vcpu_run` on the vCPU until it has
	 * injected an interrupt, sent it a message, or received
	 * `HF_VCPU_RUN_WAKE_UP` for it from another vCPU, or the timeout
	 * provided in `hf_vcpu_run_return.sleep` is not `HF_SLEEP_INDEFINITE`
	 * and the specified duration has expired.
	 */
	HF_VCPU_RUN_WAIT_FOR_MESSAGE = 3,

	/**
	 * Hafnium would like `hf_vcpu_run` to be called on another vCPU,
	 * specified by `hf_vcpu_run_return.wake_up`. The scheduler MUST either
	 * wake the vCPU in question up if it is blocked, or preempt and re-run
	 * it if it is already running somewhere. This gives Hafnium a chance to
	 * update any CPU state which might have changed.
	 */
	HF_VCPU_RUN_WAKE_UP = 4,

	/**
	 * A message has been sent by the vCPU. The scheduler MUST run a vCPU
	 * from the recipient VM and priority SHOULD be given to those vCPUs
	 * that are waiting for a message.
	 */
	HF_VCPU_RUN_MESSAGE = 5,

	/**
	 * The vCPU has made the mailbox writable and there are pending waiters.
	 * The scheduler MUST call hf_mailbox_waiter_get() repeatedly and notify
	 * all waiters by injecting an HF_MAILBOX_WRITABLE_INTID interrupt.
	 */
	HF_VCPU_RUN_NOTIFY_WAITERS = 6,

	/**
	 * The vCPU has aborted triggering the whole VM to abort. The scheduler
	 * MUST treat this as `HF_VCPU_RUN_WAIT_FOR_INTERRUPT` for this vCPU and
	 * `HF_VCPU_RUN_WAKE_UP` for all the other vCPUs of the VM.
	 */
	HF_VCPU_RUN_ABORTED = 7,
};

struct hf_vcpu_run_return {
	enum hf_vcpu_run_code code;
	union {
		struct {
			spci_vm_id_t vm_id;
			spci_vcpu_index_t vcpu;
		} wake_up;
		struct {
			spci_vm_id_t vm_id;
			uint32_t size;
		} message;
		struct {
			uint64_t ns;
		} sleep;
	};
};

enum hf_share {
	/**
	 * Relinquish ownership and access to the memory and pass them to the
	 * recipient.
	 */
	HF_MEMORY_GIVE,

	/**
	 * Retain ownership of the memory but relinquish access to the
	 * recipient.
	 */
	HF_MEMORY_LEND,

	/**
	 * Retain ownership and access but additionally allow access to the
	 * recipient.
	 */
	HF_MEMORY_SHARE,
};

/**
 * Encode an hf_vcpu_run_return struct in the SPCI ABI.
 */
static inline struct spci_value hf_vcpu_run_return_encode(
	struct hf_vcpu_run_return res, spci_vm_id_t vm_id,
	spci_vcpu_index_t vcpu_index)
{
	struct spci_value ret = {0};

	switch (res.code) {
	case HF_VCPU_RUN_PREEMPTED:
		ret.func = SPCI_INTERRUPT_32;
		ret.arg1 = (uint32_t)vm_id << 16 | vcpu_index;
		break;
	case HF_VCPU_RUN_YIELD:
		ret.func = SPCI_YIELD_32;
		ret.arg1 = (uint32_t)vcpu_index << 16 | vm_id;
		break;
	case HF_VCPU_RUN_WAIT_FOR_INTERRUPT:
		ret.func = HF_SPCI_RUN_WAIT_FOR_INTERRUPT;
		ret.arg1 = (uint32_t)vcpu_index << 16 | vm_id;
		if (res.sleep.ns == HF_SLEEP_INDEFINITE) {
			ret.arg2 = SPCI_SLEEP_INDEFINITE;
		} else if (res.sleep.ns == SPCI_SLEEP_INDEFINITE) {
			ret.arg2 = 1;
		} else {
			ret.arg2 = res.sleep.ns;
		}
		break;
	case HF_VCPU_RUN_WAIT_FOR_MESSAGE:
		ret.func = SPCI_MSG_WAIT_32;
		ret.arg1 = (uint32_t)vcpu_index << 16 | vm_id;
		if (res.sleep.ns == HF_SLEEP_INDEFINITE) {
			ret.arg2 = SPCI_SLEEP_INDEFINITE;
		} else if (res.sleep.ns == SPCI_SLEEP_INDEFINITE) {
			ret.arg2 = 1;
		} else {
			ret.arg2 = res.sleep.ns;
		}
		break;
	case HF_VCPU_RUN_WAKE_UP:
		ret.func = HF_SPCI_RUN_WAKE_UP;
		ret.arg1 = (uint32_t)res.wake_up.vcpu << 16 | res.wake_up.vm_id;
		break;
	case HF_VCPU_RUN_MESSAGE:
		ret.func = SPCI_MSG_SEND_32;
		ret.arg1 = (uint32_t)vm_id << 16 | res.message.vm_id;
		ret.arg3 = res.message.size;
		break;
	case HF_VCPU_RUN_NOTIFY_WAITERS:
		ret.func = SPCI_RX_RELEASE_32;
		break;
	case HF_VCPU_RUN_ABORTED:
		ret.func = SPCI_ERROR_32;
		ret.arg2 = SPCI_ABORTED;
		break;
	}

	return ret;
}

static spci_vm_id_t wake_up_get_vm_id(struct spci_value v)
{
	return v.arg1 & 0xffff;
}

static spci_vcpu_index_t wake_up_get_vcpu(struct spci_value v)
{
	return (v.arg1 >> 16) & 0xffff;
}

/**
 * Decode an hf_vcpu_run_return struct from the 64-bit packing ABI.
 */
static inline struct hf_vcpu_run_return hf_vcpu_run_return_decode(
	struct spci_value res)
{
	struct hf_vcpu_run_return ret = {.code = HF_VCPU_RUN_PREEMPTED};

	/* Some codes include more data. */
	switch (res.func) {
	case SPCI_INTERRUPT_32:
		ret.code = HF_VCPU_RUN_PREEMPTED;
		break;
	case SPCI_YIELD_32:
		ret.code = HF_VCPU_RUN_YIELD;
		break;
	case HF_SPCI_RUN_WAIT_FOR_INTERRUPT:
		ret.code = HF_VCPU_RUN_WAIT_FOR_INTERRUPT;
		if (res.arg2 == SPCI_SLEEP_INDEFINITE) {
			ret.sleep.ns = HF_SLEEP_INDEFINITE;
		} else {
			ret.sleep.ns = res.arg2;
		}
		break;
	case SPCI_MSG_WAIT_32:
		ret.code = HF_VCPU_RUN_WAIT_FOR_MESSAGE;
		if (res.arg2 == SPCI_SLEEP_INDEFINITE) {
			ret.sleep.ns = HF_SLEEP_INDEFINITE;
		} else {
			ret.sleep.ns = res.arg2;
		}
		break;
	case HF_SPCI_RUN_WAKE_UP:
		ret.code = HF_VCPU_RUN_WAKE_UP;
		ret.wake_up.vcpu = wake_up_get_vcpu(res);
		ret.wake_up.vm_id = wake_up_get_vm_id(res);
		break;
	case SPCI_MSG_SEND_32:
		ret.code = HF_VCPU_RUN_MESSAGE;
		ret.message.vm_id = res.arg1 & 0xffff;
		ret.message.size = res.arg3;
		break;
	case SPCI_RX_RELEASE_32:
		ret.code = HF_VCPU_RUN_NOTIFY_WAITERS;
		break;
	case SPCI_ERROR_32:
		ret.code = HF_VCPU_RUN_ABORTED;
		break;
	default:
		ret.code = HF_VCPU_RUN_ABORTED;
		break;
	}

	return ret;
}
