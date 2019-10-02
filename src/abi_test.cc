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

extern "C" {
#include "vmapi/hf/abi.h"

#include "vmapi/hf/spci.h"
}

#include <gmock/gmock.h>

namespace
{
using ::testing::Eq;

/**
 * Simulate an uninitialized spci_value so it can be detected if any
 * uninitialized fields make their way into the encoded form which would
 * indicate a data leak.
 */
struct spci_value dirty_spci_value()
{
	struct spci_value res;
	memset(&res, 0xc5, sizeof(res));
	return res;
}

/**
 * Decode a preempted response ignoring the irrelevant bits.
 */
TEST(abi, hf_vcpu_run_return_decode_preempted)
{
	struct spci_value v = dirty_spci_value();
	v.func = SPCI_INTERRUPT_32;
	struct hf_vcpu_run_return res = hf_vcpu_run_return_decode(v);
	EXPECT_THAT(res.code, Eq(HF_VCPU_RUN_PREEMPTED));
}

/**
 * Decode a yield response ignoring the irrelevant bits.
 */
TEST(abi, hf_vcpu_run_return_decode_yield)
{
	struct spci_value v = dirty_spci_value();
	v.func = SPCI_YIELD_32;
	struct hf_vcpu_run_return res = hf_vcpu_run_return_decode(v);
	EXPECT_THAT(res.code, Eq(HF_VCPU_RUN_YIELD));
}

/**
 * Decode a wait-for-interrupt response ignoring the irrelevant bits.
 */
TEST(abi, hf_vcpu_run_return_decode_wait_for_interrupt)
{
	struct spci_value v = dirty_spci_value();
	v.func = HF_SPCI_RUN_WAIT_FOR_INTERRUPT;
	v.arg2 = 0x1234abcdbadb01;
	struct hf_vcpu_run_return res = hf_vcpu_run_return_decode(v);
	EXPECT_THAT(res.code, Eq(HF_VCPU_RUN_WAIT_FOR_INTERRUPT));
	EXPECT_THAT(res.sleep.ns, Eq(0x1234abcdbadb01));
}

/**
 * Decode a wait-for-interrupt response waiting indefinitely.
 */
TEST(abi, hf_vcpu_run_return_decode_wait_for_interrupt_indefinite)
{
	struct spci_value v = dirty_spci_value();
	v.func = HF_SPCI_RUN_WAIT_FOR_INTERRUPT;
	v.arg2 = SPCI_SLEEP_INDEFINITE;
	struct hf_vcpu_run_return res = hf_vcpu_run_return_decode(v);
	EXPECT_THAT(res.code, Eq(HF_VCPU_RUN_WAIT_FOR_INTERRUPT));
	EXPECT_THAT(res.sleep.ns, Eq(HF_SLEEP_INDEFINITE));
}

/**
 * Decode a wait-for-message response ignoring the irrelevant bits.
 */
TEST(abi, hf_vcpu_run_return_decode_wait_for_message)
{
	struct spci_value v = dirty_spci_value();
	v.func = SPCI_MSG_WAIT_32;
	v.arg2 = 0x12347654badb01;
	struct hf_vcpu_run_return res = hf_vcpu_run_return_decode(v);
	EXPECT_THAT(res.code, Eq(HF_VCPU_RUN_WAIT_FOR_MESSAGE));
	EXPECT_THAT(res.sleep.ns, Eq(0x12347654badb01));
}

/**
 * Decode a wait-for-message response waiting indefinitely.
 */
TEST(abi, hf_vcpu_run_return_decode_wait_for_message_indefinite)
{
	struct spci_value v = dirty_spci_value();
	v.func = SPCI_MSG_WAIT_32;
	v.arg2 = SPCI_SLEEP_INDEFINITE;
	struct hf_vcpu_run_return res = hf_vcpu_run_return_decode(v);
	EXPECT_THAT(res.code, Eq(HF_VCPU_RUN_WAIT_FOR_MESSAGE));
	EXPECT_THAT(res.sleep.ns, Eq(HF_SLEEP_INDEFINITE));
}

/**
 * Decode a wake up response ignoring the irrelevant bits.
 */
TEST(abi, hf_vcpu_run_return_decode_wake_up)
{
	struct spci_value v = dirty_spci_value();
	v.func = HF_SPCI_RUN_WAKE_UP;
	v.arg1 = 0x88888888f00dbeef;
	struct hf_vcpu_run_return res = hf_vcpu_run_return_decode(v);
	EXPECT_THAT(res.code, Eq(HF_VCPU_RUN_WAKE_UP));
	EXPECT_THAT(res.wake_up.vm_id, Eq(0xbeef));
	EXPECT_THAT(res.wake_up.vcpu, Eq(0xf00d));
}

/**
 * Decode a wake up response ignoring the irrelevant bits.
 */
TEST(abi, hf_vcpu_run_return_decode_message)
{
	struct spci_value v = dirty_spci_value();
	v.func = SPCI_MSG_SEND_32;
	v.arg1 = 0x1111222233339162;
	v.arg3 = 0x11235813;
	struct hf_vcpu_run_return res = hf_vcpu_run_return_decode(v);
	EXPECT_THAT(res.code, Eq(HF_VCPU_RUN_MESSAGE));
	EXPECT_THAT(res.message.vm_id, Eq(0x9162));
	EXPECT_THAT(res.message.size, Eq(0x11235813));
}

/**
 * Decode a 'notify waiters' response ignoring the irrelevant bits.
 */
TEST(abi, hf_vcpu_run_return_decode_notify_waiters)
{
	struct spci_value v = dirty_spci_value();
	v.func = SPCI_RX_RELEASE_32;
	struct hf_vcpu_run_return res = hf_vcpu_run_return_decode(v);
	EXPECT_THAT(res.code, Eq(HF_VCPU_RUN_NOTIFY_WAITERS));
}

/**
 * Decode an aborted response ignoring the irrelevant bits.
 */
TEST(abi, hf_vcpu_run_return_decode_aborted)
{
	struct spci_value v = dirty_spci_value();
	v.func = SPCI_ERROR_32;
	v.arg2 = SPCI_ABORTED;
	struct hf_vcpu_run_return res = hf_vcpu_run_return_decode(v);
	EXPECT_THAT(res.code, Eq(HF_VCPU_RUN_ABORTED));
}

} /* namespace */
