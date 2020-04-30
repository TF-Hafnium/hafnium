/*
 * Copyright 2019 The Hafnium Authors.
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

#include "vmapi/hf/call.h"

#include "primary_with_secondary.h"
#include "test/hftest.h"
#include "test/vmapi/exception_handler.h"
#include "test/vmapi/ffa.h"

/**
 * Accessing unmapped memory traps the VM.
 */
TEST(unmapped, data_unmapped)
{
	struct ffa_value run_res;
	struct mailbox_buffers mb = set_up_mailbox();

	SERVICE_SELECT(SERVICE_VM1, "data_unmapped", mb.send);

	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(exception_handler_receive_exception_count(&run_res, mb.recv),
		  1);
}

/**
 * Accessing partially unmapped memory traps the VM.
 */
TEST(unmapped, straddling_data_unmapped)
{
	struct ffa_value run_res;
	struct mailbox_buffers mb = set_up_mailbox();

	SERVICE_SELECT(SERVICE_VM1, "straddling_data_unmapped", mb.send);

	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(exception_handler_receive_exception_count(&run_res, mb.recv),
		  1);
}

/**
 * Executing unmapped memory traps the VM.
 */
TEST(unmapped, instruction_unmapped)
{
	struct ffa_value run_res;
	struct mailbox_buffers mb = set_up_mailbox();

	SERVICE_SELECT(SERVICE_VM1, "instruction_unmapped", mb.send);

	run_res = ffa_run(SERVICE_VM1, 0);
	EXPECT_EQ(exception_handler_receive_exception_count(&run_res, mb.recv),
		  1);
}
