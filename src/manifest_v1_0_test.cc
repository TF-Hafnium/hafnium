/*
 * Copyright 2026 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include <span>

#include "manifest_test_helpers.hh"

namespace
{
using manifest_test::manifest_v1_0;
using manifest_test::ManifestDtBuilder;
using manifest_test::struct_manifest;
using ::testing::ElementsAre;

TEST_F(manifest_v1_0, ffa_valid_multiple_uuids)
{
	struct manifest_vm *vm;
	struct_manifest *m;

	/* clang-format off */
	std::vector<char>  dtb = ManifestDtBuilder()
		.Compatible({ "arm,ffa-manifest-1.0" })
		.Property("ffa-version", "<0x10002>")
		.Property("uuid",
			 "<0xb4b5671e 0x4a904fe1 0xb81ffb13 0xdae1dacb>,\
			  <0xb4b5671e 0x4a904fe1 0xb81ffb13 0xdae1daaa>")
		.Property("execution-ctx-count", "<1>")
		.Property("exception-level", "<2>")
		.Property("execution-state", "<0>")
		.Property("entrypoint-offset", "<0x00002000>")
		.Property("xlat-granule", "<0>")
		.Property("boot-order", "<0>")
		.Property("messaging-method", "<4>")
		.Property("ns-interrupts-action", "<1>")
		.Build();
	/* clang-format on */
	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb), MANIFEST_SUCCESS);

	vm = &m->vm[0];
	ASSERT_EQ(vm->partition.ffa_version, 0x10002);
	ASSERT_THAT(
		std::span(vm->partition.services[0].uuid.uuid, 4),
		ElementsAre(0xb4b5671e, 0x4a904fe1, 0xb81ffb13, 0xdae1dacb));
	ASSERT_THAT(
		std::span(vm->partition.services[1].uuid.uuid, 4),
		ElementsAre(0xb4b5671e, 0x4a904fe1, 0xb81ffb13, 0xdae1daaa));
	ASSERT_EQ(vm->partition.service_count, 2);
	ASSERT_EQ(vm->partition.execution_ctx_count, 1);
	ASSERT_EQ(vm->partition.run_time_el, S_EL1);
	ASSERT_EQ(vm->partition.execution_state, AARCH64);
	ASSERT_EQ(vm->partition.ep_offset, 0x00002000);
	ASSERT_EQ(vm->partition.xlat_granule, PAGE_4KB);
	ASSERT_EQ(vm->partition.boot_order, 0);
	ASSERT_EQ(vm->partition.services[0].messaging_method,
		  FFA_PARTITION_INDIRECT_MSG);
	/*
	 * If only one messaging method is provided it should apply to all
	 * services.
	 */
	ASSERT_EQ(vm->partition.services[1].messaging_method,
		  FFA_PARTITION_INDIRECT_MSG);
	ASSERT_EQ(vm->partition.ns_interrupts_action, NS_ACTION_ME);
}

TEST_F(manifest_v1_0, ffa_too_many_uuids)
{
	struct_manifest *m;

	/* clang-format off */
	std::vector<char>  dtb = ManifestDtBuilder()
		.Compatible({ "arm,ffa-manifest-1.0" })
		.Property("ffa-version", "<0x10002>")
		.Property("uuid",
			 "<0xb4b5671e 0x4a904fe1 0xb81ffb13 0xdae1dacb>,"
			  "<0xb4b5671e 0x4a904fe1 0xb81ffb13 0xdae1daaa>,"
			  "<0xb4b5671e 0x4a904fe1 0xb81ffb13 0xdae1daab>,"
			  "<0xb4b5671e 0x4a904fe1 0xb81ffb13 0xdae1daac>,"
			  "<0xb4b5671e 0x4a904fe1 0xb81ffb13 0xdae1daad>")
		.Property("execution-ctx-count", "<1>")
		.Property("exception-level", "<2>")
		.Property("execution-state", "<0>")
		.Property("entrypoint-offset", "<0x00002000>")
		.Property("xlat-granule", "<0>")
		.Property("boot-order", "<0>")
		.Property("messaging-method", "<4>")
		.Property("ns-interrupts-action", "<1>")
		.Build();
	/* clang-format on */
	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb),
		  MANIFEST_ERROR_TOO_MANY_UUIDS);
}

TEST_F(manifest_v1_0, ffa_uuid_all_zeros)
{
	struct_manifest *m;

	/* clang-format off */
	std::vector<char>  dtb = ManifestDtBuilder()
		.Compatible({ "arm,ffa-manifest-1.0" })
		.Property("ffa-version", "<0x10002>")
		.Property("uuid",
			 "<0x0 0x0 0x0 0x0>, <0x0 0x0 0x0 0x0>")
		.Property("execution-ctx-count", "<1>")
		.Property("exception-level", "<2>")
		.Property("execution-state", "<0>")
		.Property("entrypoint-offset", "<0x00002000>")
		.Property("xlat-granule", "<0>")
		.Property("boot-order", "<0>")
		.Property("messaging-method", "<4>")
		.Property("ns-interrupts-action", "<1>")
		.Build();
	/* clang-format on */
	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb),
		  MANIFEST_ERROR_UUID_ALL_ZEROS);
}

TEST_F(manifest_v1_0, ffa_valid_multiple_uuids_different_messaging_methods)
{
	struct manifest_vm *vm;
	struct_manifest *m;

	/* clang-format off */
	std::vector<char>  dtb = ManifestDtBuilder()
		.Compatible({ "arm,ffa-manifest-1.0" })
		.Property("ffa-version", "<0x10002>")
		.Property("uuid",
			 "<0xb4b5671e 0x4a904fe1 0xb81ffb13 0xdae1dacb>,\
			  <0xb4b5671e 0x4a904fe1 0xb81ffb13 0xdae1daaa>")
		.Property("execution-ctx-count", "<1>")
		.Property("exception-level", "<2>")
		.Property("execution-state", "<0>")
		.Property("entrypoint-offset", "<0x00002000>")
		.Property("xlat-granule", "<0>")
		.Property("boot-order", "<0>")
		.Property("messaging-method", "<4>,<0x6>")
		.Property("ns-interrupts-action", "<1>")
		.Build();
	/* clang-format on */
	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb), MANIFEST_SUCCESS);

	vm = &m->vm[0];
	ASSERT_EQ(vm->partition.ffa_version, 0x10002);
	ASSERT_THAT(
		std::span(vm->partition.services[0].uuid.uuid, 4),
		ElementsAre(0xb4b5671e, 0x4a904fe1, 0xb81ffb13, 0xdae1dacb));
	ASSERT_THAT(
		std::span(vm->partition.services[1].uuid.uuid, 4),
		ElementsAre(0xb4b5671e, 0x4a904fe1, 0xb81ffb13, 0xdae1daaa));
	ASSERT_EQ(vm->partition.service_count, 2);
	ASSERT_EQ(vm->partition.execution_ctx_count, 1);
	ASSERT_EQ(vm->partition.run_time_el, S_EL1);
	ASSERT_EQ(vm->partition.execution_state, AARCH64);
	ASSERT_EQ(vm->partition.ep_offset, 0x00002000);
	ASSERT_EQ(vm->partition.xlat_granule, PAGE_4KB);
	ASSERT_EQ(vm->partition.boot_order, 0);
	ASSERT_EQ(vm->partition.services[0].messaging_method,
		  FFA_PARTITION_INDIRECT_MSG);
	ASSERT_EQ(vm->partition.services[1].messaging_method,
		  FFA_PARTITION_INDIRECT_MSG | FFA_PARTITION_DIRECT_REQ_SEND);
	ASSERT_EQ(vm->partition.ns_interrupts_action, NS_ACTION_ME);
}

TEST_F(manifest_v1_0, ffa_multiple_uuids_unmatched_messaging_methods)
{
	struct_manifest *m;

	/* clang-format off */
	std::vector<char>  dtb = ManifestDtBuilder()
		.Compatible({ "arm,ffa-manifest-1.0" })
		.Property("ffa-version", "<0x10002>")
		.Property("uuid",
			 "<0xb4b5671e 0x4a904fe1 0xb81ffb13 0xdae1dacb>,\
			  <0xb4b5671e 0x4a904fe1 0xb81ffb13 0xdae1daaa>,\
			  <0xb4b5671e 0x4a904fe1 0xb81ffb13 0xdae1daab>")
		.Property("execution-ctx-count", "<1>")
		.Property("exception-level", "<2>")
		.Property("execution-state", "<0>")
		.Property("entrypoint-offset", "<0x00002000>")
		.Property("xlat-granule", "<0>")
		.Property("boot-order", "<0>")
		.Property("messaging-method", "<4>,<6>")
		.Property("ns-interrupts-action", "<1>")
		.Build();
	/* clang-format on */
	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb),
		  MANIFEST_ERROR_UNMATCHED_MESSAGING_METHODS);

	dtb = ManifestDtBuilder()
		      .Compatible({"arm,ffa-manifest-1.0"})
		      .Property("ffa-version", "<0x10002>")
		      .Property("uuid",
				"<0xb4b5671e 0x4a904fe1 0xb81ffb13 0xdae1dacb>,\
			  <0xb4b5671e 0x4a904fe1 0xb81ffb13 0xdae1daaa>,\
			  <0xb4b5671e 0x4a904fe1 0xb81ffb13 0xdae1daab>")
		      .Property("execution-ctx-count", "<1>")
		      .Property("exception-level", "<2>")
		      .Property("execution-state", "<0>")
		      .Property("entrypoint-offset", "<0x00002000>")
		      .Property("xlat-granule", "<0>")
		      .Property("boot-order", "<0>")
		      .Property("messaging-method", "<4>,<6>,<4>,<6>")
		      .Property("ns-interrupts-action", "<1>")
		      .Build();
	/* clang-format on */
	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb),
		  MANIFEST_ERROR_UNMATCHED_MESSAGING_METHODS);
}

TEST_F(manifest_v1_0, ffa_invalid_messaging_method)
{
	struct_manifest *m;

	/* clang-format off */
	std::vector<char>  dtb = ManifestDtBuilder()
		.Compatible({ "arm,ffa-manifest-1.0" })
		.Property("ffa-version", "<0x10002>")
		.Property("uuid",
			 "<0xb4b5671e 0x4a904fe1 0xb81ffb13 0xdae1dacb>")
		.Property("execution-ctx-count", "<1>")
		.Property("exception-level", "<2>")
		.Property("execution-state", "<0>")
		.Property("entrypoint-offset", "<0x00002000>")
		.Property("xlat-granule", "<0>")
		.Property("boot-order", "<0>")
		.Property("messaging-method", "<0>")
		.Property("ns-interrupts-action", "<1>")
		.Build();
	/* clang-format on */
	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb),
		  MANIFEST_ERROR_INVALID_MESSAGING_METHOD);

	/* Incompatible messaging method - unrecognized messaging-method. */
	/* clang-format off */
	dtb = ManifestDtBuilder()
		.Compatible({ "arm,ffa-manifest-1.0" })
		.Property("ffa-version", "<0x10002>")
		.Property("uuid",
			 "<0xb4b5671e 0x4a904fe1 0xb81ffb13 0xdae1dacb>")
		.Property("execution-ctx-count", "<1>")
		.Property("exception-level", "<2>")
		.Property("execution-state", "<0>")
		.Property("entrypoint-offset", "<0x00002000>")
		.Property("xlat-granule", "<0>")
		.Property("boot-order", "<0>")
		.Property("messaging-method", "<0x272>")
		.Property("ns-interrupts-action", "<1>")
		.Build();
	/* clang-format on */
	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb),
		  MANIFEST_ERROR_INVALID_MESSAGING_METHOD);
}

TEST_F(manifest_v1_0, ffa_validate_sanity_check)
{
	/*
	 * TODO: write test excluding all optional fields of the manifest, in
	 * accordance with specification.
	 */
	struct_manifest *m;

	/* Incompatible messaging method - only endpoints using FF-A version >=
	 * FF-A v1.2 are allowed to set FFA_PARTITION_DIRECT_REQ2_RECV and
	 * FFA_PARTITION_DIRECT_REQ2_SEND. */
	/* clang-format off */
	std::vector<char> dtb = ManifestDtBuilder()
		.Compatible({ "arm,ffa-manifest-1.0" })
		.Property("ffa-version", "<0x10000>")
		.Property("uuid", "<0xb4b5671e 0x4a904fe1 0xb81ffb13 0xdae1dacb>")
		.Property("execution-ctx-count", "<1>")
		.Property("exception-level", "<2>")
		.Property("execution-state", "<0>")
		.Property("entrypoint-offset", "<0x00002000>")
		.Property("xlat-granule", "<0>")
		.Property("boot-order", "<0>")
		.Property("messaging-method", "<0x204>")
		.Property("ns-interrupts-action", "<0>")
		.Build();
	/* clang-format on */
	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb),
		  MANIFEST_ERROR_NOT_COMPATIBLE);

	/*
	 * No need to invoke manifest_dealloac() since manifest TearDown calls
	 * it when the test ends.
	 */
}
} /* namespace */
