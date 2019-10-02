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
 * Simulate an uninitialized hf_vcpu_run_return so it can be detected if any
 * uninitialized fields make their way into the encoded form which would
 * indicate a data leak.
 */
struct hf_vcpu_run_return dirty_vcpu_run_return()
{
	struct hf_vcpu_run_return res;
	memset(&res, 0xc5, sizeof(res));
	return res;
}

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

bool operator==(const spci_value a, const spci_value b)
{
	return a.func == b.func && a.arg1 == b.arg1 && a.arg2 == b.arg2 &&
	       a.arg3 == b.arg3 && a.arg4 == b.arg4 && a.arg5 == b.arg5 &&
	       a.arg6 == b.arg6 && a.arg7 == b.arg7;
}

MATCHER_P(SpciEq, expected, "")
{
	return arg == expected;
}

/**
 * Encode a preempted response without leaking.
 */
TEST(abi, hf_vcpu_run_return_encode_preempted)
{
	struct hf_vcpu_run_return res = dirty_vcpu_run_return();
	res.code = HF_VCPU_RUN_PREEMPTED;
	EXPECT_THAT(hf_vcpu_run_return_encode(res, 0x1111, 0x2222),
		    SpciEq((struct spci_value){.func = SPCI_INTERRUPT_32,
					       .arg1 = 0x11112222}));
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
 * Encode a yield response without leaking.
 */
TEST(abi, hf_vcpu_run_return_encode_yield)
{
	struct hf_vcpu_run_return res = dirty_vcpu_run_return();
	res.code = HF_VCPU_RUN_YIELD;
	EXPECT_THAT(hf_vcpu_run_return_encode(res, 0x1111, 0x2222),
		    SpciEq((struct spci_value){.func = SPCI_YIELD_32,
					       .arg1 = 0x22221111}));
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
 * Encode wait-for-interrupt response without leaking.
 */
TEST(abi, hf_vcpu_run_return_encode_wait_for_interrupt)
{
	struct hf_vcpu_run_return res = dirty_vcpu_run_return();
	res.code = HF_VCPU_RUN_WAIT_FOR_INTERRUPT;
	res.sleep.ns = HF_SLEEP_INDEFINITE;
	EXPECT_THAT(hf_vcpu_run_return_encode(res, 0x1111, 0x2222),
		    SpciEq((struct spci_value){
			    .func = HF_SPCI_RUN_WAIT_FOR_INTERRUPT,
			    .arg1 = 0x22221111,
			    .arg2 = SPCI_SLEEP_INDEFINITE}));
}

/**
 * Encoding wait-for-interrupt response with large sleep duration won't drop the
 * top octet.
 */
TEST(abi, hf_vcpu_run_return_encode_wait_for_interrupt_sleep_long)
{
	struct hf_vcpu_run_return res = dirty_vcpu_run_return();
	res.code = HF_VCPU_RUN_WAIT_FOR_INTERRUPT;
	res.sleep.ns = 0xcc22888888888888;
	EXPECT_THAT(hf_vcpu_run_return_encode(res, 0x1111, 0x2222),
		    SpciEq((struct spci_value){
			    .func = HF_SPCI_RUN_WAIT_FOR_INTERRUPT,
			    .arg1 = 0x22221111,
			    .arg2 = 0xcc22888888888888}));
}

/**
 * Encoding wait-for-interrupt response with zero sleep duration will become
 * non-zero for SPCI compatibility.
 */
TEST(abi, hf_vcpu_run_return_encode_wait_for_interrupt_sleep_zero)
{
	struct hf_vcpu_run_return res = dirty_vcpu_run_return();
	res.code = HF_VCPU_RUN_WAIT_FOR_INTERRUPT;
	res.sleep.ns = 0;
	EXPECT_THAT(hf_vcpu_run_return_encode(res, 0x1111, 0x2222),
		    SpciEq((struct spci_value){
			    .func = HF_SPCI_RUN_WAIT_FOR_INTERRUPT,
			    .arg1 = 0x22221111,
			    .arg2 = 1}));
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
 * Encode wait-for-message response without leaking.
 */
TEST(abi, hf_vcpu_run_return_encode_wait_for_message)
{
	struct hf_vcpu_run_return res = dirty_vcpu_run_return();
	res.code = HF_VCPU_RUN_WAIT_FOR_MESSAGE;
	res.sleep.ns = HF_SLEEP_INDEFINITE;
	EXPECT_THAT(hf_vcpu_run_return_encode(res, 0x1111, 0x2222),
		    SpciEq((struct spci_value){.func = SPCI_MSG_WAIT_32,
					       .arg1 = 0x22221111,
					       .arg2 = SPCI_SLEEP_INDEFINITE}));
}

/**
 * Encoding wait-for-message response with large sleep duration won't drop
 * the top octet.
 */
TEST(abi, hf_vcpu_run_return_encode_wait_for_message_sleep_long)
{
	struct hf_vcpu_run_return res = dirty_vcpu_run_return();
	res.code = HF_VCPU_RUN_WAIT_FOR_MESSAGE;
	res.sleep.ns = 0xaa99777777777777;
	EXPECT_THAT(hf_vcpu_run_return_encode(res, 0x1111, 0x2222),
		    SpciEq((struct spci_value){.func = SPCI_MSG_WAIT_32,
					       .arg1 = 0x22221111,
					       .arg2 = 0xaa99777777777777}));
}

/**
 * Encoding wait-for-message response with zero sleep duration will become
 * non-zero for SPCI compatibility.
 */
TEST(abi, hf_vcpu_run_return_encode_wait_for_message_sleep_zero)
{
	struct hf_vcpu_run_return res = dirty_vcpu_run_return();
	res.code = HF_VCPU_RUN_WAIT_FOR_MESSAGE;
	res.sleep.ns = 0;
	EXPECT_THAT(hf_vcpu_run_return_encode(res, 0x1111, 0x2222),
		    SpciEq((struct spci_value){.func = SPCI_MSG_WAIT_32,
					       .arg1 = 0x22221111,
					       .arg2 = 1}));
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
 * Encode wake up response without leaking.
 */
TEST(abi, hf_vcpu_run_return_encode_wake_up)
{
	struct hf_vcpu_run_return res = dirty_vcpu_run_return();
	res.code = HF_VCPU_RUN_WAKE_UP;
	res.wake_up.vm_id = 0x1234;
	res.wake_up.vcpu = 0xabcd;
	EXPECT_THAT(hf_vcpu_run_return_encode(res, 0x1111, 0x2222),
		    SpciEq((struct spci_value){.func = HF_SPCI_RUN_WAKE_UP,
					       .arg1 = 0xabcd1234}));
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
 * Encode message response without leaking.
 */
TEST(abi, hf_vcpu_run_return_encode_message)
{
	struct hf_vcpu_run_return res = dirty_vcpu_run_return();
	res.code = HF_VCPU_RUN_MESSAGE;
	res.message.vm_id = 0xf007;
	res.message.size = 0xcafe1971;
	EXPECT_THAT(hf_vcpu_run_return_encode(res, 0x1111, 0x2222),
		    SpciEq((struct spci_value){.func = SPCI_MSG_SEND_32,
					       .arg1 = 0x1111f007,
					       .arg3 = 0xcafe1971}));
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
 * Encode a 'notify waiters' response without leaking.
 */
TEST(abi, hf_vcpu_run_return_encode_notify_waiters)
{
	struct hf_vcpu_run_return res = dirty_vcpu_run_return();
	res.code = HF_VCPU_RUN_NOTIFY_WAITERS;
	EXPECT_THAT(hf_vcpu_run_return_encode(res, 0x1111, 0x2222),
		    SpciEq((struct spci_value){.func = SPCI_RX_RELEASE_32}));
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
 * Encode an aborted response without leaking.
 */
TEST(abi, hf_vcpu_run_return_encode_aborted)
{
	struct hf_vcpu_run_return res = dirty_vcpu_run_return();
	res.code = HF_VCPU_RUN_ABORTED;
	EXPECT_THAT(
		hf_vcpu_run_return_encode(res, 0x1111, 0x2222),
		SpciEq((struct spci_value){.func = SPCI_ERROR_32,
					   .arg2 = (uint64_t)SPCI_ABORTED}));
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
