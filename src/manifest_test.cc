/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include <span>

#include "manifest_test_helpers.hh"

namespace
{
using manifest_test::manifest;
using manifest_test::ManifestDtBuilder;
using manifest_test::struct_manifest;
using ::testing::ElementsAre;
using ::testing::Eq;
using ::testing::IsEmpty;

TEST_F(manifest, no_hypervisor_node)
{
	struct_manifest *m;
	std::vector<char> dtb = ManifestDtBuilder().Build();

	ASSERT_EQ(manifest_from_vec(&m, dtb),
		  MANIFEST_ERROR_NO_HYPERVISOR_FDT_NODE);
}

TEST_F(manifest, no_compatible_property)
{
	struct_manifest *m;

	/* clang-format off */
	std::vector<char> dtb = ManifestDtBuilder()
		.StartChild("hypervisor")
		.EndChild()
		.Build();
	/* clang-format on */

	ASSERT_EQ(manifest_from_vec(&m, dtb), MANIFEST_ERROR_NOT_COMPATIBLE);
}

TEST_F(manifest, not_compatible)
{
	struct_manifest *m;

	/* clang-format off */
	std::vector<char> dtb = ManifestDtBuilder()
		.StartChild("hypervisor")
			.Compatible({ "foo,bar" })
		.EndChild()
		.Build();
	/* clang-format on */

	ASSERT_EQ(manifest_from_vec(&m, dtb), MANIFEST_ERROR_NOT_COMPATIBLE);
}

TEST_F(manifest, compatible_one_of_many)
{
	struct_manifest *m;

	/* clang-format off */
	std::vector<char> dtb = ManifestDtBuilder()
		.StartChild("hypervisor")
			.Compatible({ "foo,bar", "hafnium,hafnium" })
			.StartChild("vm1")
				.DebugName("primary")
			.EndChild()
		.EndChild()
		.Build();
	/* clang-format on */

	ASSERT_EQ(manifest_from_vec(&m, dtb), MANIFEST_SUCCESS);
}

TEST_F(manifest, no_vm_nodes)
{
	struct_manifest *m;

	/* clang-format off */
	std::vector<char> dtb = ManifestDtBuilder()
		.StartChild("hypervisor")
			.Compatible()
		.EndChild()
		.Build();
	/* clang-format on */

	ASSERT_EQ(manifest_from_vec(&m, dtb), MANIFEST_ERROR_NO_PRIMARY_VM);
}

static std::vector<char> gen_long_string_dtb(bool valid)
{
	const char last_valid[] = "123456789012345678901234567890123456";
	const char first_invalid[] = "1234567890123456789012345678901234567";
	static_assert(sizeof(last_valid) == STRING_MAX_SIZE);
	static_assert(sizeof(first_invalid) == STRING_MAX_SIZE + 1);

	/* clang-format off */
	return ManifestDtBuilder()
		.StartChild("hypervisor")
			.Compatible()
			.StartChild("vm1")
				.DebugName(valid ? last_valid : first_invalid)
			.EndChild()
		.EndChild()
		.Build();
	/* clang-format on */
}

TEST_F(manifest, long_string)
{
	struct_manifest *m;
	std::vector<char> dtb_last_valid = gen_long_string_dtb(true);
	std::vector<char> dtb_first_invalid = gen_long_string_dtb(false);

	ASSERT_EQ(manifest_from_vec(&m, dtb_last_valid), MANIFEST_SUCCESS);
	manifest_dealloc();

	ASSERT_EQ(manifest_from_vec(&m, dtb_first_invalid),
		  MANIFEST_ERROR_STRING_TOO_LONG);
}

TEST_F(manifest, reserved_vm_id)
{
	struct_manifest *m;

	/* clang-format off */
	std::vector<char> dtb = ManifestDtBuilder()
		.StartChild("hypervisor")
			.Compatible()
			.StartChild("vm1")
				.DebugName("primary_vm")
			.EndChild()
			.StartChild("vm0")
				.DebugName("reserved_vm")
				.VcpuCount(1)
				.MemSize(0x1000)
				.KernelFilename("kernel")
			.EndChild()
		.EndChild()
		.Build();
	/* clang-format on */

	ASSERT_EQ(manifest_from_vec(&m, dtb), MANIFEST_ERROR_RESERVED_VM_ID);
}

static std::vector<char> gen_vcpu_count_limit_dtb(uint32_t vcpu_count)
{
	/* clang-format off */
	return ManifestDtBuilder()
		.StartChild("hypervisor")
			.Compatible()
			.StartChild("vm1")
				.DebugName("primary_vm")
			.EndChild()
			.StartChild("vm2")
				.DebugName("secondary_vm")
				.VcpuCount(vcpu_count)
				.MemSize(0x1000)
				.KernelFilename("kernel")
			.EndChild()
		.EndChild()
		.Build();
	/* clang-format on */
}

TEST_F(manifest, vcpu_count_limit)
{
	struct_manifest *m;
	std::vector<char> dtb_last_valid = gen_vcpu_count_limit_dtb(UINT16_MAX);
	std::vector<char> dtb_first_invalid =
		gen_vcpu_count_limit_dtb(UINT16_MAX + 1);

	ASSERT_EQ(manifest_from_vec(&m, dtb_last_valid), MANIFEST_SUCCESS);
	ASSERT_EQ(m->vm_count, 2);
	ASSERT_EQ(m->vm[1].secondary.vcpu_count, UINT16_MAX);
	manifest_dealloc();

	ASSERT_EQ(manifest_from_vec(&m, dtb_first_invalid),
		  MANIFEST_ERROR_INTEGER_OVERFLOW);
}

TEST_F(manifest, no_ramdisk_primary)
{
	struct_manifest *m;

	/* clang-format off */
	std::vector<char> dtb = ManifestDtBuilder()
		.StartChild("hypervisor")
			.Compatible()
			.StartChild("vm1")
				.DebugName("primary_vm")
			.EndChild()
		.EndChild()
		.Build();
	/* clang-format on */

	ASSERT_EQ(manifest_from_vec(&m, dtb), MANIFEST_SUCCESS);
	ASSERT_EQ(m->vm_count, 1);
	ASSERT_STREQ(string_data(&m->vm[0].debug_name), "primary_vm");
	ASSERT_STREQ(string_data(&m->vm[0].primary.ramdisk_filename), "");
}

TEST_F(manifest, no_boot_address_primary)
{
	struct_manifest *m;

	/* clang-format off */
	std::vector<char> dtb = ManifestDtBuilder()
		.StartChild("hypervisor")
			.Compatible()
			.StartChild("vm1")
				.DebugName("primary_vm")
			.EndChild()
		.EndChild()
		.Build();
	/* clang-format on */

	ASSERT_EQ(manifest_from_vec(&m, dtb), MANIFEST_SUCCESS);
	ASSERT_EQ(m->vm_count, 1);
	ASSERT_STREQ(string_data(&m->vm[0].debug_name), "primary_vm");
	ASSERT_EQ(m->vm[0].primary.boot_address, MANIFEST_INVALID_ADDRESS);
}

TEST_F(manifest, boot_address_primary)
{
	struct_manifest *m;
	const uint64_t addr = UINT64_C(0x12345678ABCDEFEF);

	/* clang-format off */
	std::vector<char> dtb = ManifestDtBuilder()
		.StartChild("hypervisor")
			.Compatible()
			.StartChild("vm1")
				.DebugName("primary_vm")
				.BootAddress(addr)
			.EndChild()
		.EndChild()
		.Build();
	/* clang-format on */

	ASSERT_EQ(manifest_from_vec(&m, dtb), MANIFEST_SUCCESS);
	ASSERT_EQ(m->vm_count, 1);
	ASSERT_STREQ(string_data(&m->vm[0].debug_name), "primary_vm");
	ASSERT_EQ(m->vm[0].primary.boot_address, addr);
}

static std::vector<char> gen_malformed_boolean_dtb(
	const std::string_view &value)
{
	/* clang-format off */
	return  ManifestDtBuilder()
		.StartChild("hypervisor")
			.Compatible()
			.StartChild("vm1")
				.DebugName("primary_vm")
				.Property("smc_whitelist_permissive", value)
			.EndChild()
		.EndChild()
		.Build();
	/* clang-format on */
}

TEST_F(manifest, malformed_booleans)
{
	struct_manifest *m;

	std::vector<char> dtb_false = gen_malformed_boolean_dtb("\"false\"");
	std::vector<char> dtb_true = gen_malformed_boolean_dtb("\"true\"");
	std::vector<char> dtb_0 = gen_malformed_boolean_dtb("\"<0>\"");
	std::vector<char> dtb_1 = gen_malformed_boolean_dtb("\"<1>\"");

	ASSERT_EQ(manifest_from_vec(&m, dtb_false),
		  MANIFEST_ERROR_MALFORMED_BOOLEAN);
	manifest_dealloc();

	ASSERT_EQ(manifest_from_vec(&m, dtb_true),
		  MANIFEST_ERROR_MALFORMED_BOOLEAN);
	manifest_dealloc();

	ASSERT_EQ(manifest_from_vec(&m, dtb_0),
		  MANIFEST_ERROR_MALFORMED_BOOLEAN);
	manifest_dealloc();

	ASSERT_EQ(manifest_from_vec(&m, dtb_1),
		  MANIFEST_ERROR_MALFORMED_BOOLEAN);
}

TEST_F(manifest, valid)
{
	struct_manifest *m;
	struct manifest_vm *vm;

	/* clang-format off */
	std::vector<char> dtb = ManifestDtBuilder()
		.StartChild("hypervisor")
			.Compatible()
			.StartChild("vm1")
				.DebugName("primary_vm")
				.KernelFilename("primary_kernel")
				.RamdiskFilename("primary_ramdisk")
				.SmcWhitelist({0x32000000, 0x33001111})
			.EndChild()
			.StartChild("vm3")
				.DebugName("second_secondary_vm")
				.VcpuCount(43)
				.MemSize(0x12345)
				.KernelFilename("second_secondary_kernel")
			.EndChild()
			.StartChild("vm2")
				.DebugName("first_secondary_vm")
				.VcpuCount(42)
				.MemSize(12345)
				.SmcWhitelist({0x04000000, 0x30002222, 0x31445566})
				.SmcWhitelistPermissive()
			.EndChild()
		.EndChild()
		.Build();
	/* clang-format on */

	ASSERT_EQ(manifest_from_vec(&m, dtb), MANIFEST_SUCCESS);
	ASSERT_EQ(m->vm_count, 3);

	vm = &m->vm[0];
	ASSERT_STREQ(string_data(&vm->debug_name), "primary_vm");
	ASSERT_STREQ(string_data(&vm->kernel_filename), "primary_kernel");
	ASSERT_STREQ(string_data(&vm->primary.ramdisk_filename),
		     "primary_ramdisk");
	ASSERT_THAT(
		std::span(vm->smc_whitelist.smcs, vm->smc_whitelist.smc_count),
		ElementsAre(0x32000000, 0x33001111));
	ASSERT_FALSE(vm->smc_whitelist.permissive);

	vm = &m->vm[1];
	ASSERT_STREQ(string_data(&vm->debug_name), "first_secondary_vm");
	ASSERT_STREQ(string_data(&vm->kernel_filename), "");
	ASSERT_EQ(vm->secondary.vcpu_count, 42);
	ASSERT_EQ(vm->secondary.mem_size, 12345);
	ASSERT_THAT(
		std::span(vm->smc_whitelist.smcs, vm->smc_whitelist.smc_count),
		ElementsAre(0x04000000, 0x30002222, 0x31445566));
	ASSERT_TRUE(vm->smc_whitelist.permissive);

	vm = &m->vm[2];
	ASSERT_STREQ(string_data(&vm->debug_name), "second_secondary_vm");
	ASSERT_STREQ(string_data(&vm->kernel_filename),
		     "second_secondary_kernel");
	ASSERT_EQ(vm->secondary.vcpu_count, 43);
	ASSERT_EQ(vm->secondary.mem_size, 0x12345);
	ASSERT_THAT(
		std::span(vm->smc_whitelist.smcs, vm->smc_whitelist.smc_count),
		IsEmpty());
	ASSERT_FALSE(vm->smc_whitelist.permissive);
}

TEST_F(manifest, ffa_not_compatible)
{
	struct_manifest *m;

	/* clang-format off */
	std::vector<char>  dtb = ManifestDtBuilder()
		.Compatible({ "arm,ffa-manifest-2.0" })
		.Property("ffa-version", "<0x10000>")
		.Property("execution-ctx-count", "<1>")
		.Property("exception-level", "<2>")
		.Property("execution-state", "<0>")
		.Property("entrypoint-offset", "<0x00002000>")
		.Property("xlat-granule", "<0>")
		.Property("ns-interrupts-action", "<1>")
		.StartChild("services")
			.Compatible({ "arm,ffa-manifest-services"})
			.StartChild("service0")
				.Property("messaging-method", "<1>")
				.StringProperty("uuid", "b4b5671e-4a90-4fe1-b81f-fb13dae1dacb")
			.EndChild()
		.EndChild()
		.Build();
	/* clang-format on */

	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb),
		  MANIFEST_ERROR_NOT_COMPATIBLE);
}

TEST_F(manifest, ffa_missing_services)
{
	struct_manifest *m;

	/* clang-format off */
	std::vector<char>  dtb = ManifestDtBuilder()
		.Compatible({ "arm,ffa-manifest-1.1" })
		.Property("ffa-version", "<0x10000>")
		.Build();
	/* clang-format on */

	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb), MANIFEST_ERROR_NO_SERVICES);

	/* clang-format off */
	dtb = ManifestDtBuilder()
		.Compatible({"arm,ffa-manifest-1.1"})
		.Property("ffa-version", "<0x10000>")
		.StartChild("services")
		      .Compatible({"arm,ffa-manifest-services"})
		.EndChild()
		.Build();
	/* clang-format on */

	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb), MANIFEST_ERROR_NO_SERVICES);
}

TEST_F(manifest, ffa_missing_property)
{
	struct_manifest *m;

	/* clang-format off */
	std::vector<char>  dtb = ManifestDtBuilder()
		.Compatible({ "arm,ffa-manifest-1.1" })
		.Property("ffa-version", "<0x10000>")
		.StartChild("services")
			.Compatible({ "arm,ffa-manifest-services"})
			.StartChild("service0")
				.Property("messaging-method", "<1>")
				.StringProperty("uuid", "b4b5671e-4a90-4fe1-b81f-fb13dae1dacb")
			.EndChild()
		.EndChild()
		.Build();
	/* clang-format on */

	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb),
		  MANIFEST_ERROR_PROPERTY_NOT_FOUND);
}

TEST_F(manifest, ffa_duplicate_uuid)
{
	struct_manifest *m;

	/* clang-format off */
	std::vector<char>  dtb = ManifestDtBuilder()
		.Compatible({ "arm,ffa-manifest-1.1" })
		.Property("ffa-version", "<0x10000>")
		.Property("execution-ctx-count", "<1>")
		.Property("exception-level", "<2>")
		.Property("execution-state", "<0>")
		.Property("entrypoint-offset", "<0x00002000>")
		.Property("xlat-granule", "<0>")
		.Property("boot-order", "<0>")
		.Property("ns-interrupts-action", "<1>")
		.StartChild("services")
			.Compatible({ "arm,ffa-manifest-services"})
			.StartChild("service0")
				.Property("messaging-method", "<1>")
				.StringProperty("uuid", "b4b5671e-4a90-4fe1-b81f-fb13dae1dacb")
			.EndChild()
			.StartChild("service1")
				.Property("messaging-method", "<1>")
				.StringProperty("uuid", "b4b5671e-4a90-4fe1-b81f-fb13dae1dacb")
			.EndChild()
		.EndChild()
		.Build();
	/* clang-format on */

	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb),
		  MANIFEST_ERROR_DUPLICATE_UUID);
}

TEST_F(manifest, ffa_validate_sanity_check)
{
	/*
	 * TODO: write test excluding all optional fields of the manifest, in
	 * accordance with specification.
	 */
	struct_manifest *m;

	/* Incompatible version */
	/* clang-format off */
	std::vector<char>  dtb = ManifestDtBuilder()
		.Compatible({ "arm,ffa-manifest-1.1" })
		.Property("ffa-version", "<0xa1>")
		.Property("execution-ctx-count", "<1>")
		.Property("exception-level", "<2>")
		.Property("execution-state", "<0>")
		.Property("entrypoint-offset", "<0x00002000>")
		.Property("xlat-granule", "<0>")
		.Property("boot-order", "<0>")
		.Property("ns-interrupts-action", "<1>")
		.StartChild("services")
			.Compatible({ "arm,ffa-manifest-services"})
			.StartChild("service0")
				.Property("messaging-method", "<1>")
				.StringProperty("uuid", "b4b5671e-4a90-4fe1-b81f-fb13dae1dacb")
			.EndChild()
		.EndChild()
		.Build();
	/* clang-format on */
	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb),
		  MANIFEST_ERROR_NOT_COMPATIBLE);
	manifest_dealloc();

	/* Incompatible translation granule */
	/* clang-format off */
	dtb = ManifestDtBuilder()
		.Compatible({ "arm,ffa-manifest-1.1" })
		.Property("ffa-version", "<0x10000>")
		.Property("execution-ctx-count", "<1>")
		.Property("exception-level", "<2>")
		.Property("execution-state", "<0>")
		.Property("entrypoint-offset", "<0x00002000>")
		.Property("xlat-granule", "<3>")
		.Property("boot-order", "<0>")
		.Property("ns-interrupts-action", "<1>")
		.StartChild("services")
			.Compatible({ "arm,ffa-manifest-services"})
			.StartChild("service0")
				.Property("messaging-method", "<1>")
				.StringProperty("uuid", "b4b5671e-4a90-4fe1-b81f-fb13dae1dacb")
			.EndChild()
		.EndChild()
		.Build();
	/* clang-format on */
	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb),
		  MANIFEST_ERROR_NOT_COMPATIBLE);
	manifest_dealloc();

	/* Incompatible exeption level */
	/* clang-format off */
	dtb = ManifestDtBuilder()
		.Compatible({ "arm,ffa-manifest-1.1" })
		.Property("ffa-version", "<0x10000>")
		.Property("execution-ctx-count", "<1>")
		.Property("exception-level", "<10>")
		.Property("execution-state", "<0>")
		.Property("entrypoint-offset", "<0x00002000>")
		.Property("xlat-granule", "<0>")
		.Property("boot-order", "<0>")
		.Property("ns-interrupts-action", "<0>")
		.StartChild("services")
			.Compatible({ "arm,ffa-manifest-services"})
			.StartChild("service0")
				.Property("messaging-method", "<1>")
				.StringProperty("uuid", "b4b5671e-4a90-4fe1-b81f-fb13dae1dacb")
			.EndChild()
		.EndChild()
		.Build();
	/* clang-format on */
	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb),
		  MANIFEST_ERROR_NOT_COMPATIBLE);
	manifest_dealloc();

	/* Incompatible execution state */
	/* clang-format off */
	dtb = ManifestDtBuilder()
		.Compatible({ "arm,ffa-manifest-1.1" })
		.Property("ffa-version", "<0x10000>")
		.Property("execution-ctx-count", "<1>")
		.Property("exception-level", "<2>")
		.Property("execution-state", "<2>")
		.Property("entrypoint-offset", "<0x00002000>")
		.Property("xlat-granule", "<0>")
		.Property("boot-order", "<0>")
		.Property("ns-interrupts-action", "<0>")
		.StartChild("services")
			.Compatible({ "arm,ffa-manifest-services"})
			.StartChild("service0")
				.Property("messaging-method", "<1>")
				.StringProperty("uuid", "b4b5671e-4a90-4fe1-b81f-fb13dae1dacb")
			.EndChild()
		.EndChild()
		.Build();
	/* clang-format on */
	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb),
		  MANIFEST_ERROR_NOT_COMPATIBLE);
	manifest_dealloc();

	/* Incompatible messaging method - only endpoints using FF-A version >=
	 * FF-A v1.2 are allowed to set FFA_PARTITION_DIRECT_REQ2_RECV and
	 * FFA_PARTITION_DIRECT_REQ2_SEND. */
	/* clang-format off */
	dtb = ManifestDtBuilder()
		.Compatible({ "arm,ffa-manifest-1.1" })
		.Property("ffa-version", "<0x10000>")
		.Property("execution-ctx-count", "<1>")
		.Property("exception-level", "<2>")
		.Property("execution-state", "<0>")
		.Property("entrypoint-offset", "<0x00002000>")
		.Property("xlat-granule", "<0>")
		.Property("boot-order", "<0>")
		.Property("ns-interrupts-action", "<0>")
		.StartChild("services")
			.Compatible({ "arm,ffa-manifest-services"})
			.StartChild("service0")
				.Property("messaging-method", "<0x204>")
				.StringProperty("uuid", "b4b5671e-4a90-4fe1-b81f-fb13dae1dacb")
			.EndChild()
		.EndChild()
		.Build();
	/* clang-format on */
	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb),
		  MANIFEST_ERROR_NOT_COMPATIBLE);

	/*
	 * No need to invoke manifest_dealloac() since manifest TearDown calls
	 * it when the test ends.
	 */
}

TEST_F(manifest, ffa_validate_interrupt_actions)
{
	struct_manifest *m;

	/* Incompatible NS interrupt action */
	/* clang-format off */
	std::vector<char>  dtb = ManifestDtBuilder()
		.Compatible({ "arm,ffa-manifest-1.1" })
		.Property("ffa-version", "<0x10000>")
		.Property("execution-ctx-count", "<1>")
		.Property("exception-level", "<2>")
		.Property("execution-state", "<0>")
		.Property("entrypoint-offset", "<0x00002000>")
		.Property("xlat-granule", "<0>")
		.Property("boot-order", "<0>")
		.Property("ns-interrupts-action", "<4>")
		.StartChild("services")
			.Compatible({ "arm,ffa-manifest-services"})
			.StartChild("service0")
				.Property("messaging-method", "<1>")
				.StringProperty("uuid", "b4b5671e-4a90-4fe1-b81f-fb13dae1dacb")
			.EndChild()
		.EndChild()
		.Build();
	/* clang-format on */
	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb),
		  MANIFEST_ERROR_ILLEGAL_NS_INT_ACTION);
	manifest_dealloc();

	/* Incompatible other-s-interrupts-action for S-EL1 partition */
	/* clang-format off */
	dtb = ManifestDtBuilder()
		.Compatible({ "arm,ffa-manifest-1.1" })
		.Property("ffa-version", "<0x10000>")
		.Property("execution-ctx-count", "<1>")
		.Property("exception-level", "<2>")
		.Property("execution-state", "<0>")
		.Property("entrypoint-offset", "<0x00002000>")
		.Property("xlat-granule", "<0>")
		.Property("boot-order", "<0>")
		.Property("ns-interrupts-action", "<1>")
		.Property("other-s-interrupts-action", "<0>")
		.StartChild("services")
			.Compatible({ "arm,ffa-manifest-services"})
			.StartChild("service0")
				.Property("messaging-method", "<1>")
				.StringProperty("uuid", "b4b5671e-4a90-4fe1-b81f-fb13dae1dacb")
			.EndChild()
		.EndChild()
		.Build();
	/* clang-format on */
	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb),
		  MANIFEST_ERROR_NOT_COMPATIBLE);
	manifest_dealloc();

	/*
	 * Incompatible choice of the fields ns-interrupts-action and
	 * other-s-interrupts-action.
	 */
	/* clang-format off */
	dtb = ManifestDtBuilder()
		.Compatible({ "arm,ffa-manifest-1.1" })
		.Property("ffa-version", "<0x10000>")
		.Property("execution-ctx-count", "<1>")
		.Property("exception-level", "<1>")
		.Property("execution-state", "<0>")
		.Property("entrypoint-offset", "<0x00002000>")
		.Property("xlat-granule", "<0>")
		.Property("boot-order", "<0>")
		.Property("ns-interrupts-action", "<2>")
		.Property("other-s-interrupts-action", "<0>")
		.StartChild("services")
			.Compatible({ "arm,ffa-manifest-services"})
			.StartChild("service0")
				.Property("messaging-method", "<1>")
				.StringProperty("uuid", "b4b5671e-4a90-4fe1-b81f-fb13dae1dacb")
			.EndChild()
		.EndChild()
		.Build();
	/* clang-format on */
	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb),
		  MANIFEST_ERROR_NOT_COMPATIBLE);
	manifest_dealloc();

	/* Illegal value specified for the field other-s-interrupts-action. */
	/* clang-format off */
	dtb = ManifestDtBuilder()
		.Compatible({ "arm,ffa-manifest-1.1" })
		.Property("ffa-version", "<0x10000>")
		.Property("execution-ctx-count", "<1>")
		.Property("exception-level", "<1>")
		.Property("execution-state", "<0>")
		.Property("entrypoint-offset", "<0x00002000>")
		.Property("xlat-granule", "<0>")
		.Property("boot-order", "<0>")
		.Property("other-s-interrupts-action", "<2>")
		.StartChild("services")
			.Compatible({ "arm,ffa-manifest-services"})
			.StartChild("service0")
				.Property("messaging-method", "<1>")
				.StringProperty("uuid", "b4b5671e-4a90-4fe1-b81f-fb13dae1dacb")
			.EndChild()
		.EndChild()
		.Build();
	/* clang-format on */
	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb),
		  MANIFEST_ERROR_ILLEGAL_OTHER_S_INT_ACTION);
}

TEST_F(manifest, vm_availability_messages)
{
	struct manifest_vm *vm;
	struct_manifest *m;
	std::vector<char> dtb;

	/* clang-format off */
	dtb = ManifestDtBuilder()
		.Compatible({ "arm,ffa-manifest-1.1" })
		.Property("ffa-version", "<0x10001>")
		.Property("execution-ctx-count", "<8>")
		.Property("exception-level", "<2>")
		.Property("execution-state", "<0>")
		.Property("entrypoint-offset", "<0x00002000>")
		.Property("vm-availability-messages", "<0>")
		.StartChild("services")
			.Compatible({ "arm,ffa-manifest-services"})
			.StartChild("service0")
				.Property("messaging-method", "<1>")
				.StringProperty("uuid", "b4b5671e-4a90-4fe1-b81f-fb13dae1dacb")
			.EndChild()
		.EndChild()
		.Build();
	/* clang-format on */
	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb), MANIFEST_SUCCESS);
	vm = &m->vm[0];
	ASSERT_EQ(vm->partition.vm_availability_messages.vm_created, 0);
	ASSERT_EQ(vm->partition.vm_availability_messages.vm_destroyed, 0);
	ASSERT_EQ(vm->partition.vm_availability_messages.mbz, 0);
	manifest_dealloc();

	/* clang-format off */
	dtb = ManifestDtBuilder()
		.Compatible({ "arm,ffa-manifest-1.1" })
		.Property("ffa-version", "<0x10001>")
		.Property("execution-ctx-count", "<8>")
		.Property("exception-level", "<2>")
		.Property("execution-state", "<0>")
		.Property("entrypoint-offset", "<0x00002000>")
		.Property("vm-availability-messages", "<1>")
		.StartChild("services")
			.Compatible({ "arm,ffa-manifest-services"})
			.StartChild("service0")
				.Property("messaging-method", "<1>")
				.StringProperty("uuid", "b4b5671e-4a90-4fe1-b81f-fb13dae1dacb")
			.EndChild()
		.EndChild()
		.Build();
	/* clang-format on */
	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb), MANIFEST_SUCCESS);
	vm = &m->vm[0];
	ASSERT_EQ(vm->partition.vm_availability_messages.vm_created, 1);
	ASSERT_EQ(vm->partition.vm_availability_messages.vm_destroyed, 0);
	ASSERT_EQ(vm->partition.vm_availability_messages.mbz, 0);
	manifest_dealloc();

	/* clang-format off */
	dtb = ManifestDtBuilder()
		.Compatible({ "arm,ffa-manifest-1.1" })
		.Property("ffa-version", "<0x10001>")
		.Property("execution-ctx-count", "<8>")
		.Property("exception-level", "<2>")
		.Property("execution-state", "<0>")
		.Property("entrypoint-offset", "<0x00002000>")
		.Property("vm-availability-messages", "<2>")
		.StartChild("services")
			.Compatible({ "arm,ffa-manifest-services"})
			.StartChild("service0")
				.Property("messaging-method", "<1>")
				.StringProperty("uuid", "b4b5671e-4a90-4fe1-b81f-fb13dae1dacb")
			.EndChild()
		.EndChild()
		.Build();
	/* clang-format on */
	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb), MANIFEST_SUCCESS);
	vm = &m->vm[0];
	ASSERT_EQ(vm->partition.vm_availability_messages.vm_created, 0);
	ASSERT_EQ(vm->partition.vm_availability_messages.vm_destroyed, 1);
	ASSERT_EQ(vm->partition.vm_availability_messages.mbz, 0);
	manifest_dealloc();

	/* clang-format off */
	dtb = ManifestDtBuilder()
		.Compatible({ "arm,ffa-manifest-1.1" })
		.Property("ffa-version", "<0x10001>")
		.Property("execution-ctx-count", "<8>")
		.Property("exception-level", "<2>")
		.Property("execution-state", "<0>")
		.Property("entrypoint-offset", "<0x00002000>")
		.Property("vm-availability-messages", "<3>")
		.StartChild("services")
			.Compatible({ "arm,ffa-manifest-services"})
			.StartChild("service0")
				.Property("messaging-method", "<1>")
				.StringProperty("uuid", "b4b5671e-4a90-4fe1-b81f-fb13dae1dacb")
			.EndChild()
		.EndChild()
		.Build();
	/* clang-format on */
	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb), MANIFEST_SUCCESS);
	vm = &m->vm[0];
	ASSERT_EQ(vm->partition.vm_availability_messages.vm_created, 1);
	ASSERT_EQ(vm->partition.vm_availability_messages.vm_destroyed, 1);
	ASSERT_EQ(vm->partition.vm_availability_messages.mbz, 0);
	manifest_dealloc();

	/* clang-format off */
	dtb = ManifestDtBuilder()
		.Compatible({ "arm,ffa-manifest-1.1" })
		.Property("ffa-version", "<0x10001>")
		.Property("execution-ctx-count", "<8>")
		.Property("exception-level", "<2>")
		.Property("execution-state", "<0>")
		.Property("entrypoint-offset", "<0x00002000>")
		.StartChild("services")
			.Compatible({ "arm,ffa-manifest-services"})
			.StartChild("service0")
				.Property("messaging-method", "<1>")
				.StringProperty("uuid", "b4b5671e-4a90-4fe1-b81f-fb13dae1dacb")
			.EndChild()
		.EndChild()
		.Build();
	/* clang-format on */
	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb), MANIFEST_SUCCESS);
	vm = &m->vm[0];
	ASSERT_EQ(vm->partition.vm_availability_messages.vm_created, 0);
	ASSERT_EQ(vm->partition.vm_availability_messages.vm_destroyed, 0);
	ASSERT_EQ(vm->partition.vm_availability_messages.mbz, 0);
	manifest_dealloc();

	/* clang-format off */
	dtb = ManifestDtBuilder()
		.Compatible({ "arm,ffa-manifest-1.1" })
		.Property("ffa-version", "<0x10001>")
		.Property("execution-ctx-count", "<8>")
		.Property("exception-level", "<2>")
		.Property("execution-state", "<0>")
		.Property("entrypoint-offset", "<0x00002000>")
		.Property("vm-availability-messages", "<4>")
		.StartChild("services")
			.Compatible({ "arm,ffa-manifest-services"})
			.StartChild("service0")
				.Property("messaging-method", "<2>")
				.StringProperty("uuid", "b4b5671e-4a90-4fe1-b81f-fb13dae1dacb")
			.EndChild()
		.EndChild()
		.Build();
	/* clang-format on */
	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb),
		  MANIFEST_ERROR_VM_AVAILABILITY_MESSAGE_INVALID);
	vm = &m->vm[0];
	ASSERT_EQ(vm->partition.vm_availability_messages.vm_created, 0);
	ASSERT_EQ(vm->partition.vm_availability_messages.vm_destroyed, 0);
	ASSERT_NE(vm->partition.vm_availability_messages.mbz, 0);
	manifest_dealloc();
}

TEST_F(manifest, power_management)
{
	struct manifest_vm *vm;
	struct_manifest *m;

	/* S-EL1 partition power management field can only set bit 0. */
	/* clang-format off */
	std::vector<char>  dtb = ManifestDtBuilder()
		.Compatible({ "arm,ffa-manifest-1.1" })
		.Property("ffa-version", "<0x10001>")
		.Property("execution-ctx-count", "<8>")
		.Property("exception-level", "<2>")
		.Property("execution-state", "<0>")
		.Property("entrypoint-offset", "<0x00002000>")
		.Property("power-management-messages", "<0xf>")
		.StartChild("services")
			.Compatible({ "arm,ffa-manifest-services"})
			.StartChild("service0")
				.Property("messaging-method", "<1>")
				.StringProperty("uuid", "b4b5671e-4a90-4fe1-b81f-fb13dae1dacb")
			.EndChild()
		.EndChild()
		.Build();
	/* clang-format on */
	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb), MANIFEST_SUCCESS);
	vm = &m->vm[0];
	ASSERT_EQ(vm->partition.power_management, 1);
	manifest_dealloc();

	/* S-EL0 partition power management field is forced to 0. */
	/* clang-format off */
	dtb = ManifestDtBuilder()
		.Compatible({ "arm,ffa-manifest-1.1" })
		.Property("ffa-version", "<0x10001>")
		.Property("execution-ctx-count", "<1>")
		.Property("exception-level", "<1>")
		.Property("execution-state", "<0>")
		.Property("entrypoint-offset", "<0x00002000>")
		.Property("power-management-messages", "<0xff>")
		.StartChild("services")
			.Compatible({ "arm,ffa-manifest-services"})
			.StartChild("service0")
				.Property("messaging-method", "<1>")
				.StringProperty("uuid", "b4b5671e-4a90-4fe1-b81f-fb13dae1dacb")
			.EndChild()
		.EndChild()
		.Build();
	/* clang-format on */
	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb), MANIFEST_SUCCESS);
	vm = &m->vm[0];
	ASSERT_EQ(vm->partition.power_management, 0);
}

TEST_F(manifest, ffa_validate_rxtx_info)
{
	struct_manifest *m;

	/* Not Compatible */
	/* clang-format off */
	std::vector<char>  dtb = ManifestDtBuilder()
		.FfaValidManifest()
		.StartChild("rx_tx-info")
			.Compatible({ "foo,bar" })
		.EndChild()
		.Build();
	/* clang-format on */
	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb),
		  MANIFEST_ERROR_NOT_COMPATIBLE);
	manifest_dealloc();

	/* Missing Properties */
	/* clang-format off */
	dtb = ManifestDtBuilder()
		.FfaValidManifest()
		.StartChild("rx_tx-info")
			.Compatible({ "arm,ffa-manifest-rx_tx-buffer" })
		.EndChild()
		.Build();
	/* clang-format on */
	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb),
		  MANIFEST_ERROR_PROPERTY_NOT_FOUND);
}

TEST_F(manifest, ffa_validate_mem_regions_not_compatible)
{
	struct_manifest *m;
	std::vector<char> dtb;

	/* Not Compatible */
	/* clang-format off */
	dtb = ManifestDtBuilder()
		.FfaValidManifest()
		.StartChild("memory-regions")
			.Compatible({ "foo,bar" })
		.EndChild()
		.Build();
	/* clang-format on */
	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb),
		  MANIFEST_ERROR_NOT_COMPATIBLE);
	manifest_dealloc();
}

TEST_F(manifest, ffa_validate_mem_regions_unavailable)
{
	struct_manifest *m;
	std::vector<char> dtb;

	/* Memory regions unavailable  */
	/* clang-format off */
	dtb = ManifestDtBuilder()
		.FfaValidManifest()
		.StartChild("memory-regions")
			.Compatible({ "arm,ffa-manifest-memory-regions" })
		.EndChild()
		.Build();
	/* clang-format on */
	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb),
		  MANIFEST_ERROR_MEMORY_REGION_NODE_EMPTY);
	manifest_dealloc();
}

TEST_F(manifest, ffa_validate_mem_regions_missing_properties)
{
	struct_manifest *m;
	std::vector<char> dtb;

	/* Missing Properties */
	/* clang-format off */
	dtb = ManifestDtBuilder()
		.FfaValidManifest()
		.StartChild("memory-regions")
			.Compatible({ "arm,ffa-manifest-memory-regions" })
			.StartChild("test-memory")
				.Description("test-memory")
			.EndChild()
		.EndChild()
		.Build();
	/* clang-format on */
	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb),
		  MANIFEST_ERROR_PROPERTY_NOT_FOUND);
	manifest_dealloc();
}

TEST_F(manifest, ffa_validate_mem_regions_empty_region)
{
	struct_manifest *m;
	std::vector<char> dtb;

	/* Empty memory region */
	/* clang-format off */
	dtb = ManifestDtBuilder()
		.FfaValidManifest()
		.StartChild("memory-regions")
			.Compatible({ "arm,ffa-manifest-memory-regions" })
			.Label("rx")
			.StartChild("rx")
				.Description("rx-buffer")
				.Property("base-address", "<0x7300000>")
				.Property("pages-count", "<0>")
				.Property("attributes", "<1>")
			.EndChild()
			.Label("tx")
			.StartChild("tx")
				.Description("tx-buffer")
				.Property("base-address", "<0x7310000>")
				.Property("pages-count", "<2>")
				.Property("attributes", "<3>")
			.EndChild()
		.EndChild()
		.StartChild("rx_tx-info")
			.Compatible({ "arm,ffa-manifest-rx_tx-buffer" })
			.Property("rx-buffer", "<&rx>")
			.Property("tx-buffer", "<&tx>")
		.EndChild()
		.Build();
	/* clang-format on */
	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb),
		  MANIFEST_ERROR_MEM_REGION_EMPTY);
	manifest_dealloc();
}

TEST_F(manifest, ffa_validate_mem_regions_base_address_and_relative_offset)
{
	struct_manifest *m;
	std::vector<char> dtb;

	/* Mutually exclusive base-address and load-address-relative-offset
	 * properties */
	/* clang-format off */
	dtb = ManifestDtBuilder()
		.FfaValidManifest()
		.StartChild("memory-regions")
			.Compatible({ "arm,ffa-manifest-memory-regions" })
			.Label("rx")
			.StartChild("rx")
				.Description("rx-buffer")
				.Property("base-address", "<0x7300000>")
				.Property("load-address-relative-offset", "<0x7300000>")
				.Property("pages-count", "<1>")
				.Property("attributes", "<1>")
			.EndChild()
		.EndChild()
		.Build();
	/* clang-format on */
	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb),
		  MANIFEST_ERROR_BASE_ADDRESS_AND_RELATIVE_ADDRESS);
	manifest_dealloc();
}

TEST_F(manifest, ffa_validate_mem_regions_relative_address_overflow)
{
	struct_manifest *m;
	std::vector<char> dtb;

	/* Relative-address overflow*/
	/* clang-format off */
	dtb = ManifestDtBuilder()
		.FfaValidManifest()
		.Property("load-address", "<0xffffff00 0xffffff00>")
		.StartChild("memory-regions")
			.Compatible({ "arm,ffa-manifest-memory-regions" })
			.Label("rx")
			.StartChild("rx")
				.Description("rx-buffer")
				.Property("load-address-relative-offset", "<0xffffff00 0xffffff00>")
				.Property("pages-count", "<1>")
				.Property("attributes", "<1>")
			.EndChild()
		.EndChild()
		.Build();
	/* clang-format on */
	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb),
		  MANIFEST_ERROR_INTEGER_OVERFLOW);
	manifest_dealloc();
}

TEST_F(manifest, ffa_validate_mem_regions_relative_offset_valid)
{
	struct_manifest *m;
	std::vector<char> dtb;

	/* valid relative offset */
	/* clang-format off */
	dtb = ManifestDtBuilder()
		.FfaValidManifest()
		.Property("load-address", "<0xffffff00 0xffffff00>")
		.StartChild("memory-regions")
			.Compatible({ "arm,ffa-manifest-memory-regions" })
			.Label("rx")
			.StartChild("rx")
				.Description("rx-buffer")
				.Property("load-address-relative-offset", "<0x1000>")
				.Property("pages-count", "<1>")
				.Property("attributes", "<1>")
			.EndChild()
		.EndChild()
		.Build();
	/* clang-format on */
	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb), MANIFEST_SUCCESS);
	manifest_dealloc();
}

TEST_F(manifest, ffa_validate_mem_regions_overlapping)
{
	struct_manifest *m;
	std::vector<char> dtb;

	/* Overlapping memory regions */
	/* clang-format off */
	dtb = ManifestDtBuilder()
		.FfaValidManifest()
		.StartChild("memory-regions")
			.Compatible({ "arm,ffa-manifest-memory-regions" })
			.Label("rx")
			.StartChild("rx")
				.Description("rx-buffer")
				.Property("base-address", "<0x7300000>")
				.Property("pages-count", "<1>")
				.Property("attributes", "<1>")
			.EndChild()
			.Label("tx")
			.StartChild("tx")
				.Description("tx-buffer")
				.Property("base-address", "<0x7300000>")
				.Property("pages-count", "<2>")
				.Property("attributes", "<3>")
			.EndChild()
		.EndChild()
		.Build();
	/* clang-format on */
	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb),
		  MANIFEST_ERROR_MEM_REGION_OVERLAP);
	manifest_dealloc();

	/* clang-format off */
	dtb = ManifestDtBuilder()
		.FfaValidManifest()
		.StartChild("memory-regions")
			.Compatible({ "arm,ffa-manifest-memory-regions" })
			.Label("rx")
			.StartChild("rx")
				.Description("rx-buffer")
				.Property("load-address-relative-offset", "<0x0>")
				.Property("pages-count", "<1>")
				.Property("attributes", "<1>")
			.EndChild()
			.Label("tx")
			.StartChild("tx")
				.Description("tx-buffer")
				.Property("load-address-relative-offset", "<0x0>")
				.Property("pages-count", "<2>")
				.Property("attributes", "<3>")
			.EndChild()
		.EndChild()
		.Build();
	/* clang-format on */
	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb),
		  MANIFEST_ERROR_MEM_REGION_OVERLAP);
	manifest_dealloc();

	/* clang-format off */
	dtb = ManifestDtBuilder()
		.FfaValidManifest()
		.StartChild("memory-regions")
			.Compatible({ "arm,ffa-manifest-memory-regions" })
			.Label("rx")
			.StartChild("rx")
				.Description("rx-buffer")
				.Property("base-address", "<0x7300000>")
				.Property("pages-count", "<2>")
				.Property("attributes", "<1>")
			.EndChild()
			.Label("tx")
			.StartChild("tx")
				.Description("tx-buffer")
				.Property("base-address", "<0x7301000>")
				.Property("pages-count", "<2>")
				.Property("attributes", "<3>")
			.EndChild()
		.EndChild()
		.Build();
	/* clang-format on */
	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb),
		  MANIFEST_ERROR_MEM_REGION_OVERLAP);
	manifest_dealloc();

	/* clang-format off */
	dtb = ManifestDtBuilder()
		.FfaValidManifest()
		.StartChild("memory-regions")
			.Compatible({ "arm,ffa-manifest-memory-regions" })
			.Label("rx")
			.StartChild("rx")
				.Description("rx-buffer")
				.Property("base-address", "<0x7301000>")
				.Property("pages-count", "<1>")
				.Property("attributes", "<1>")
			.EndChild()
			.Label("tx")
			.StartChild("tx")
				.Description("tx-buffer")
				.Property("base-address", "<0x7300000>")
				.Property("pages-count", "<2>")
				.Property("attributes", "<3>")
			.EndChild()
		.EndChild()
		.Build();
	/* clang-format on */
	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb),
		  MANIFEST_ERROR_MEM_REGION_OVERLAP);
	manifest_dealloc();

	/* clang-format off */
	Partition_package spkg(dtb);
	dtb = ManifestDtBuilder()
		.FfaValidManifest()
		.StartChild("memory-regions")
			.Compatible({ "arm,ffa-manifest-memory-regions" })
			.StartChild("test-memory")
				.Description("test-memory")
				.Integer64Property("base-address", (uint64_t)&spkg,true)
				.Property("pages-count", "<1>")
				.Property("attributes", "<1>")
			.EndChild()
		.EndChild()
		.Build(true);
	/* clang-format on */
	spkg.init(dtb);
	ASSERT_EQ(ffa_manifest_from_spkg(&m, &spkg),
		  MANIFEST_ERROR_MEM_REGION_OVERLAP);
	manifest_dealloc();
}

TEST_F(manifest, ffa_validate_mem_regions_overlapping_allowed)
{
	struct_manifest *m;
	std::vector<char> dtb;

	/*
	 * Mem regions are allowed to overlap with parent `load-address` if the
	 * `load-address-relative-offset` was specified.
	 */
	/* clang-format off */
	dtb = ManifestDtBuilder()
		.FfaValidManifest()
		.StartChild("memory-regions")
			.Compatible({ "arm,ffa-manifest-memory-regions" })
			.Label("rx")
			.StartChild("rx")
				.Description("rx-buffer")
				.Property("load-address-relative-offset", "<0x1000>")
				.Property("pages-count", "<1>")
				.Property("attributes", "<1>")
			.EndChild()
			.Label("tx")
			.StartChild("tx")
				.Description("tx-buffer")
				.Property("base-address", "<0x7300000>")
				.Property("pages-count", "<2>")
				.Property("attributes", "<3>")
			.EndChild()
		.EndChild()
		.Build();
	/* clang-format on */
	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb), MANIFEST_SUCCESS);
	ASSERT_EQ(m->vm[0].partition.mem_regions[0].is_relative, true);
	ASSERT_EQ(m->vm[0].partition.mem_regions[0].base_address,
		  m->vm[0].partition.load_addr + 0x1000);
	manifest_dealloc();

	/* clang-format off */
	dtb = ManifestDtBuilder()
		.FfaValidManifest()
		.StartChild("memory-regions")
			.Compatible({ "arm,ffa-manifest-memory-regions" })
			.Label("rx")
			.StartChild("rx")
				.Description("rx-buffer")
				.Property("base-address", "<0x7300000>")
				.Property("pages-count", "<1>")
				.Property("attributes", "<1>")
			.EndChild()
			.Label("tx")
			.StartChild("tx")
				.Description("tx-buffer")
				.Property("load-address-relative-offset", "<0x1000>")
				.Property("pages-count", "<2>")
				.Property("attributes", "<3>")
			.EndChild()
		.EndChild()
		.Build();
	/* clang-format on */
	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb), MANIFEST_SUCCESS);
	ASSERT_EQ(m->vm[0].partition.mem_regions[1].is_relative, true);
	ASSERT_EQ(m->vm[0].partition.mem_regions[1].base_address,
		  m->vm[0].partition.load_addr + 0x1000);
	manifest_dealloc();
}

TEST_F(manifest, ffa_validate_mem_regions_unaligned)
{
	struct_manifest *m;
	std::vector<char> dtb;

	/* Unaligned memory region */
	/* clang-format off */
	dtb = ManifestDtBuilder()
		.FfaValidManifest()
		.StartChild("memory-regions")
			.Compatible({ "arm,ffa-manifest-memory-regions" })
			.Label("rx")
			.StartChild("rx")
				.Description("rx-buffer")
				.Property("base-address", "<0x7300FFF>")
				.Property("pages-count", "<2>")
				.Property("attributes", "<1>")
			.EndChild()
			.Label("tx")
			.StartChild("tx")
				.Description("tx-buffer")
				.Property("base-address", "<0x7303000>")
				.Property("pages-count", "<2>")
				.Property("attributes", "<3>")
			.EndChild()
		.EndChild()
		.Build();
	/* clang-format on */
	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb),
		  MANIFEST_ERROR_MEM_REGION_UNALIGNED);
	manifest_dealloc();
}

TEST_F(manifest, ffa_validate_mem_regions_different_rxtx_sizes)
{
	struct_manifest *m;
	std::vector<char> dtb;

	/* Different RXTX buffer sizes */
	/* clang-format off */
	dtb = ManifestDtBuilder()
		.FfaValidManifest()
		.StartChild("memory-regions")
			.Compatible({ "arm,ffa-manifest-memory-regions" })
			.Label("rx")
			.StartChild("rx")
				.Description("rx-buffer")
				.Property("base-address", "<0x7300000>")
				.Property("pages-count", "<1>")
				.Property("attributes", "<1>")
			.EndChild()
			.Label("tx")
			.StartChild("tx")
				.Description("tx-buffer")
				.Property("base-address", "<0x7310000>")
				.Property("pages-count", "<2>")
				.Property("attributes", "<3>")
			.EndChild()
		.EndChild()
		.StartChild("rx_tx-info")
			.Compatible({ "arm,ffa-manifest-rx_tx-buffer" })
			.Property("rx-buffer", "<&rx>")
			.Property("tx-buffer", "<&tx>")
		.EndChild()
		.Build();
	/* clang-format on */
	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb),
		  MANIFEST_ERROR_RXTX_SIZE_MISMATCH);
}

TEST_F(manifest, ffa_validate_dev_regions)
{
	struct_manifest *m;

	/* Not Compatible */
	/* clang-format off */
	std::vector<char>  dtb = ManifestDtBuilder()
		.FfaValidManifest()
		.StartChild("device-regions")
			.Compatible({ "foo,bar" })
		.EndChild()
		.Build();
	/* clang-format on */
	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb),
		  MANIFEST_ERROR_NOT_COMPATIBLE);
	manifest_dealloc();

	/* Memory regions unavailable  */
	/* clang-format off */
	dtb = ManifestDtBuilder()
		.FfaValidManifest()
		.StartChild("device-regions")
			.Compatible({ "arm,ffa-manifest-device-regions" })
		.EndChild()
		.Build();
	/* clang-format on */
	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb),
		  MANIFEST_ERROR_DEVICE_REGION_NODE_EMPTY);
	manifest_dealloc();

	/* Missing Properties */
	/* clang-format off */
	dtb = ManifestDtBuilder()
		.FfaValidManifest()
		.StartChild("device-regions")
			.Compatible({ "arm,ffa-manifest-device-regions" })
			.StartChild("test-device")
				.Description("test-device")
			.EndChild()
		.EndChild()
		.Build();
	/* clang-format on */
	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb),
		  MANIFEST_ERROR_PROPERTY_NOT_FOUND);
	manifest_dealloc();

	/* Malformed interrupt list pair */
	/* clang-format off */
	dtb = ManifestDtBuilder()
		.FfaValidManifest()
		.StartChild("device-regions")
			.Compatible({ "arm,ffa-manifest-device-regions" })
			.StartChild("test-device")
				.Description("test-device")
				.Property("base-address", "<0x24000000>")
				.Property("pages-count", "<16>")
				.Property("attributes", "<3>")
				.Property("smmu-id", "<1>")
				.Property("stream-ids", "<0 1>")
				.Property("interrupts", "<2 3>, <4>")
			.EndChild()
		.EndChild()
		.Build();
	/* clang-format on */
	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb),
		  MANIFEST_ERROR_MALFORMED_INTEGER_LIST);
	manifest_dealloc();

	/* Non-unique interrupt IDs */
	/* clang-format off */
	dtb = ManifestDtBuilder()
		.FfaValidManifest()
		.StartChild("device-regions")
			.Compatible({ "arm,ffa-manifest-device-regions" })
			.StartChild("test-device-0")
				.Description("test-device-0")
				.Property("base-address", "<0x24000000>")
				.Property("pages-count", "<16>")
				.Property("attributes", "<3>")
				.Property("interrupts", "<2 3>")
			.EndChild()
			.StartChild("test-device-1")
				.Description("test-device-1")
				.Property("base-address", "<0x25000000>")
				.Property("pages-count", "<16>")
				.Property("attributes", "<3>")
				.Property("interrupts", "<1 3>, <2 5> ")
			.EndChild()
		.EndChild()
		.Build();

	/* clang-format on */
	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb),
		  MANIFEST_ERROR_INTERRUPT_ID_REPEATED);
	/* Check valid interrupts were still mapped */
	ASSERT_EQ(m->vm[0].partition.dev_regions[0].interrupts[0].id, 2);
	ASSERT_EQ(m->vm[0].partition.dev_regions[0].interrupts[0].attributes,
		  3);
	ASSERT_EQ(m->vm[0].partition.dev_regions[1].interrupts[0].id, 1);
	ASSERT_EQ(m->vm[0].partition.dev_regions[1].interrupts[0].attributes,
		  3);
	manifest_dealloc();

	/* Overlapping address space between two device region nodes. */
	/* clang-format off */
	dtb = ManifestDtBuilder()
		.FfaValidManifest()
		.StartChild("device-regions")
			.Compatible({"arm,ffa-manifest-device-regions"})
			.StartChild("test-device-0")
				.Description("test-device-0")
				.Property("base-address", "<0x24000000>")
				.Property("pages-count", "<16>")
				.Property("attributes", "<3>")
			.EndChild()
			.StartChild("test-device-1")
				.Description("test-device-1")
				.Property("base-address", "<0x24000000>")
				.Property("pages-count", "<16>")
				.Property("attributes", "<3>")
			.EndChild()
		.EndChild()
		.Build();

	/* clang-format on */
	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb),
		  MANIFEST_ERROR_MEM_REGION_OVERLAP);
	manifest_dealloc();

	/*
	 * Device regions cannot be defined outside of the regions specified in
	 * the spmc.
	 */
	/* clang-format off */
	dtb = ManifestDtBuilder()
		.FfaValidManifest()
		.StartChild("device-regions")
			.Compatible({"arm,ffa-manifest-device-regions"})
			.StartChild("test-device-0")
				.Description("test-device-0")
				.Property("base-address", "<0x50000000>")
				.Property("pages-count", "<16>")
				.Property("attributes", "<3>")
			.EndChild()
		.EndChild()
		.Build();
	/* clang-format on */
	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb),
		  MANIFEST_ERROR_DEVICE_MEM_REGION_INVALID);
	manifest_dealloc();

	/*
	 * Memory defined as NS in SPMC manifest given Secure attribute should
	 * fail.
	 */
	/* clang-format off */
	dtb = ManifestDtBuilder()
		.FfaValidManifest()
		.StartChild("device-regions")
			.Compatible({"arm,ffa-manifest-device-regions"})
			.StartChild("test-device-0")
				.Description("test-device-0")
				.Property("base-address", "<0x20000000>")
				.Property("pages-count", "<16>")
				.Property("attributes", "<3>")
			.EndChild()
		.EndChild()
		.Build();
	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb),
		  MANIFEST_ERROR_DEVICE_MEM_REGION_INVALID);
}

TEST_F(manifest, ffa_invalid_memory_region_attributes)
{
	struct_manifest *m;

	/* clang-format off */
	std::vector<char>  dtb = ManifestDtBuilder()
		.FfaValidManifest()
		.StartChild("rx_tx-info")
			.Compatible({ "arm,ffa-manifest-rx_tx-buffer" })
			.Property("rx-buffer", "<&rx>")
			.Property("tx-buffer", "<&tx>")
		.EndChild()
		.StartChild("memory-regions")
			.Compatible({ "arm,ffa-manifest-memory-regions" })
			.StartChild("test-memory")
				.Description("test-memory")
				.Property("base-address", "<0x7100000>")
				.Property("pages-count", "<4>")
				.Property("attributes", "<7>")
			.EndChild()
			.Label("rx")
			.StartChild("rx")
				.Description("rx-buffer")
				.Property("base-address", "<0x7300000>")
				.Property("pages-count", "<1>")
				.Property("attributes", "<1>")
			.EndChild()
			.Label("tx")
			.StartChild("tx")
				.Description("tx-buffer")
				.Property("base-address", "<0x7310000>")
				.Property("pages-count", "<1>")
				.Property("attributes", "<3>")
			.EndChild()
		.EndChild()
		.Build();
	/* clang-format on */

	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb),
		  MANIFEST_ERROR_INVALID_MEM_PERM);
}

TEST_F(manifest, ffa_invalid_device_region_attributes)
{
	struct_manifest *m;

	/* clang-format off */
	std::vector<char>  dtb = ManifestDtBuilder()
		.FfaValidManifest()
		.StartChild("rx_tx-info")
			.Compatible({ "arm,ffa-manifest-rx_tx-buffer" })
			.Property("rx-buffer", "<&rx>")
			.Property("tx-buffer", "<&tx>")
		.EndChild()
		.StartChild("memory-regions")
			.Compatible({ "arm,ffa-manifest-memory-regions" })
			.StartChild("test-memory")
				.Description("test-memory")
				.Property("base-address", "<0x7100000>")
				.Property("pages-count", "<4>")
				.Property("attributes", "<3>")
			.EndChild()
			.Label("rx")
			.StartChild("rx")
				.Description("rx-buffer")
				.Property("base-address", "<0x7300000>")
				.Property("pages-count", "<1>")
				.Property("attributes", "<1>")
			.EndChild()
			.Label("tx")
			.StartChild("tx")
				.Description("tx-buffer")
				.Property("base-address", "<0x7310000>")
				.Property("pages-count", "<1>")
				.Property("attributes", "<3>")
			.EndChild()
		.EndChild()
		.StartChild("device-regions")
			.Compatible({ "arm,ffa-manifest-device-regions" })
			.StartChild("test-device")
				.Description("test-device")
				.Property("base-address", "<0x7200000>")
				.Property("pages-count", "<16>")
				.Property("attributes", "<5>")
				.Property("smmu-id", "<1>")
				.Property("stream-ids", "<0 1>")
				.Property("interrupts", "<2 3>, <4 5>")
			.EndChild()
		.EndChild()
		.Build();
	/* clang-format on */

	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb),
		  MANIFEST_ERROR_INVALID_MEM_PERM);
}

TEST_F(manifest, ffa_valid)
{
	struct manifest_vm *vm;
	struct_manifest *m;

	/* clang-format off */
	std::vector<char>  dtb = ManifestDtBuilder()
		.FfaValidManifest()
		.StartChild("rx_tx-info")
			.Compatible({ "arm,ffa-manifest-rx_tx-buffer" })
			.Property("rx-buffer", "<&rx>")
			.Property("tx-buffer", "<&tx>")
		.EndChild()
		.StartChild("memory-regions")
			.Compatible({ "arm,ffa-manifest-memory-regions" })
			.StartChild("test-memory-ns")
				.Description("test-memory")
				.Property("base-address", "<0x7200000>")
				.Property("pages-count", "<1>")
				.Property("attributes", "<0xb>")
			.EndChild()
			.Label("rx")
			.StartChild("rx")
				.Description("rx-buffer")
				.Property("base-address", "<0x7300000>")
				.Property("pages-count", "<1>")
				.Property("attributes", "<1>")
			.EndChild()
			.Label("tx")
			.StartChild("tx")
				.Description("tx-buffer")
				.Property("base-address", "<0x7301000>")
				.Property("pages-count", "<1>")
				.Property("attributes", "<3>")
			.EndChild()
		.EndChild()
		.StartChild("device-regions")
			.Compatible({ "arm,ffa-manifest-device-regions" })
			.StartChild("test-device")
				.Description("test-device")
				.Property("base-address", "<0x24000000>")
				.Property("pages-count", "<16>")
				.Property("attributes", "<3>")
				.Property("smmu-id", "<1>")
				.Property("stream-ids", "<0 1>")
				.Property("interrupts", "<2 3>, <4 5>")
			.EndChild()
			.StartChild("test-device-ns")
				.Description("test-device")
				.Property("base-address", "<0x20000000>")
				.Property("pages-count", "<1>")
				.Property("attributes", "<0x9>")
			.EndChild()
		.EndChild()
		.Build();

	/* clang-format on */
	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb), MANIFEST_SUCCESS);

	vm = &m->vm[0];
	ASSERT_EQ(vm->partition.ffa_version, 0x10000);
	ASSERT_THAT(
		std::span(vm->partition.services[0].uuid.uuid, 4),
		ElementsAre(0xb4b5671e, 0x4a904fe1, 0xb81ffb13, 0xdae1dacb));
	ASSERT_EQ(vm->partition.execution_ctx_count, 1);
	ASSERT_EQ(vm->partition.run_time_el, S_EL1);
	ASSERT_EQ(vm->partition.execution_state, AARCH64);
	ASSERT_EQ(vm->partition.ep_offset, 0x00002000);
	ASSERT_EQ(vm->partition.xlat_granule, PAGE_4KB);
	ASSERT_EQ(vm->partition.boot_order, 0);
	ASSERT_EQ(vm->partition.services[0].messaging_method,
		  FFA_PARTITION_INDIRECT_MSG);
	ASSERT_EQ(vm->partition.ns_interrupts_action, NS_ACTION_ME);
	ASSERT_EQ(vm->partition.mem_regions[0].attributes, (8 | 3));

	ASSERT_EQ(vm->partition.rxtx.available, true);
	ASSERT_EQ(vm->partition.rxtx.rx_buffer->base_address, 0x7300000);
	ASSERT_EQ(vm->partition.rxtx.rx_buffer->page_count, 1);
	ASSERT_EQ(vm->partition.rxtx.rx_buffer->attributes, 1);
	ASSERT_EQ(vm->partition.rxtx.tx_buffer->base_address, 0x7301000);
	ASSERT_EQ(vm->partition.rxtx.tx_buffer->page_count, 1);
	ASSERT_EQ(vm->partition.rxtx.tx_buffer->attributes, 3);

	ASSERT_EQ(vm->partition.dev_regions[0].base_address, 0x24000000);
	ASSERT_EQ(vm->partition.dev_regions[0].page_count, 16);
	ASSERT_EQ(vm->partition.dev_regions[0].attributes, 3);
	ASSERT_EQ(vm->partition.dev_regions[0].dma_prop.smmu_id, 1);
	ASSERT_EQ(vm->partition.dev_regions[0].dma_prop.stream_ids[0], 0);
	ASSERT_EQ(vm->partition.dev_regions[0].dma_prop.stream_ids[1], 1);
	ASSERT_EQ(vm->partition.dev_regions[0].interrupts[0].id, 2);
	ASSERT_EQ(vm->partition.dev_regions[0].interrupts[0].attributes, 3);
	ASSERT_EQ(vm->partition.dev_regions[0].interrupts[1].id, 4);
	ASSERT_EQ(vm->partition.dev_regions[0].interrupts[1].attributes, 5);
	ASSERT_EQ(vm->partition.dev_regions[1].base_address, 0x20000000);
	ASSERT_EQ(vm->partition.dev_regions[1].attributes, (8 | 1));
}

TEST_F(manifest, ffa_valid_interrupt_target_manifest)
{
	struct manifest_vm *vm;
	struct_manifest *m;

	/* clang-format off */
	std::vector<char>  dtb = ManifestDtBuilder()
		.FfaValidManifest()
		.StartChild("device-regions")
			.Compatible({ "arm,ffa-manifest-device-regions" })
			.StartChild("test-device")
				.Description("test-device")
				.Property("base-address", "<0x24000000>")
				.Property("pages-count", "<16>")
				.Property("attributes", "<3>")
				.Property("smmu-id", "<1>")
				.Property("stream-ids", "<0 1>")
				.Property("interrupts", "<2 3>, <4 5>")
				.Property("interrupts-target", "<2 0x1234 0x5678>, <4 0x12345678 0x87654321>")
			.EndChild()
		.EndChild()
		.Build();
	/* clang-format on */

	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb), MANIFEST_SUCCESS);

	vm = &m->vm[0];

	ASSERT_EQ(vm->partition.dev_regions[0].base_address, 0x24000000);
	ASSERT_EQ(vm->partition.dev_regions[0].page_count, 16);
	ASSERT_EQ(vm->partition.dev_regions[0].attributes, 3);
	ASSERT_EQ(vm->partition.dev_regions[0].dma_prop.smmu_id, 1);
	ASSERT_EQ(vm->partition.dev_regions[0].dma_prop.stream_ids[0], 0);
	ASSERT_EQ(vm->partition.dev_regions[0].dma_prop.stream_ids[1], 1);
	ASSERT_EQ(vm->partition.dev_regions[0].interrupts[0].id, 2);
	ASSERT_EQ(vm->partition.dev_regions[0].interrupts[0].attributes, 3);
	ASSERT_EQ(vm->partition.dev_regions[0].interrupts[0].mpidr_valid, true);
	ASSERT_EQ(vm->partition.dev_regions[0].interrupts[0].mpidr,
		  0x123400005678);
	ASSERT_EQ(vm->partition.dev_regions[0].interrupts[1].id, 4);
	ASSERT_EQ(vm->partition.dev_regions[0].interrupts[1].attributes, 5);
	ASSERT_EQ(vm->partition.dev_regions[0].interrupts[1].mpidr_valid, true);
	ASSERT_EQ(vm->partition.dev_regions[0].interrupts[1].mpidr,
		  0x1234567887654321);
}

TEST_F(manifest, ffa_invalid_interrupt_target_manifest)
{
	struct_manifest *m;

	/* clang-format off */
	std::vector<char>  dtb = ManifestDtBuilder()
		.FfaValidManifest()
		.StartChild("device-regions")
			.Compatible({ "arm,ffa-manifest-device-regions" })
			.StartChild("test-device")
				.Description("test-device")
				.Property("base-address", "<0x24000000>")
				.Property("pages-count", "<16>")
				.Property("attributes", "<3>")
				.Property("smmu-id", "<1>")
				.Property("stream-ids", "<0 1>")
				.Property("interrupts", "<2 3>, <4 5>")
				.Property("interrupts-target", "<20 0x1234 0x5678>")
			.EndChild()
		.EndChild()
		.Build();
	/* clang-format on */

	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb),
		  MANIFEST_ERROR_INTERRUPT_ID_NOT_IN_LIST);
}

TEST_F(manifest, sri_policy)
{
	struct_manifest *m;
	std::vector<char> dtb;

	/* clang-format off */
	dtb = ManifestDtBuilder()
		.FfaValidManifest()
		.Property("sri-interrupts-policy", "<0x0>")
		.Build();
	/* clang-format on */

	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb), MANIFEST_SUCCESS);

	/* clang-format off */
	dtb = ManifestDtBuilder()
		.FfaValidManifest()
		.Property("sri-interrupts-policy", "<0x1>")
		.Build();
	/* clang-format on */

	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb), MANIFEST_SUCCESS);

	/* clang-format off */
	dtb = ManifestDtBuilder()
		.FfaValidManifest()
		.Property("sri-interrupts-policy", "<0x2>")
		.Build();
	/* clang-format on */

	/* clang-format off */
	dtb = ManifestDtBuilder()
		.FfaValidManifest()
		.Property("sri-interrupts-policy", "<0x3>")
		.Build();
	/* clang-format on */

	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb), MANIFEST_SUCCESS);

	/* clang-format off */
	dtb = ManifestDtBuilder()
		.FfaValidManifest()
		.Property("sri-interrupts-policy", "<0xF>")
		.Build();
	/* clang-format on */

	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb),
		  MANIFEST_ERROR_ILLEGAL_SRI_POLICY);
}

TEST_F(manifest, ffa_boot_order_not_unique)
{
	struct_manifest *m;
	struct memiter it;
	struct mm_stage1_locked mm_stage1_locked = mm_lock_stage1();
	struct boot_params params;
	Partition_package spkg_1;
	Partition_package spkg_2;

	/* clang-format off */
	std::vector<char>  dtb1 = ManifestDtBuilder()
		.Compatible({ "arm,ffa-manifest-1.1" })
		.Property("ffa-version", "<0x10001>")
		.FfaLoadAddress((uint64_t)&spkg_1)
		.Property("execution-ctx-count", "<1>")
		.Property("exception-level", "<1>")
		.Property("execution-state", "<0>")
		.Property("entrypoint-offset", "<0x00002000>")
		.Property("xlat-granule", "<0>")
		.Property("boot-order", "<1>")
		.Property("ns-interrupts-action", "<0>")
		.StartChild("services")
			.Compatible({ "arm,ffa-manifest-services"})
			.StartChild("service0")
				.Property("messaging-method", "<1>")
				.StringProperty("uuid", "b4b5671e-4a90-4fe1-b81f-fb13dae1dacb")
			.EndChild()
		.EndChild()
		.Build();

	std::vector<char> dtb2 = ManifestDtBuilder()
		.Compatible({ "arm,ffa-manifest-1.1" })
		.Property("ffa-version", "<0x10001>")
		.FfaLoadAddress((uint64_t)&spkg_2)
		.Property("execution-ctx-count", "<1>")
		.Property("exception-level", "<1>")
		.Property("execution-state", "<0>")
		.Property("entrypoint-offset", "<0x00002000>")
		.Property("xlat-granule", "<0>")
		.Property("boot-order", "<1>")
		.Property("ns-interrupts-action", "<0>")
		.StartChild("services")
			.Compatible({ "arm,ffa-manifest-services"})
			.StartChild("service0")
				.Property("messaging-method", "<1>")
				.StringProperty("uuid", "b4b5671e-4a90-4fe1-b81f-fb13dae1daaa")
			.EndChild()
		.EndChild()
		.Build();

	/* clang-format on */
	spkg_1.init(dtb1);
	spkg_2.init(dtb2);

	/* clang-format off */
	std::vector<char> core_dtb = ManifestDtBuilder()
		.StartChild("hypervisor")
			.Compatible()
			.StartChild("vm1")
				.DebugName("ffa_partition_1")
				.FfaPartition()
				.LoadAddress((uint64_t)&spkg_1)
				.VcpuCount(1)
				.MemSize(0x10000000)
			.EndChild()
			.StartChild("vm2")
				.DebugName("ffa_partition_2")
				.FfaPartition()
				.LoadAddress((uint64_t)&spkg_2)
				.VcpuCount(1)
				.MemSize(0x10000000)
			.EndChild()
		.EndChild()
		.Build();
	/* clang-format on */

	boot_params_init(&params, nullptr);
	memiter_init(&it, core_dtb.data(), core_dtb.size());
	ASSERT_EQ(manifest_init(mm_stage1_locked, &m, &it, &params),
		  MANIFEST_ERROR_INVALID_BOOT_ORDER);

	mm_unlock_stage1(&mm_stage1_locked);
}

TEST_F(manifest, ffa_valid_multiple_uuids)
{
	struct manifest_vm *vm;
	struct_manifest *m;

	/* clang-format off */
	std::vector<char>  dtb = ManifestDtBuilder()
		.Compatible({ "arm,ffa-manifest-1.1" })
		.Property("ffa-version", "<0x10002>")
		.Property("execution-ctx-count", "<1>")
		.Property("exception-level", "<2>")
		.Property("execution-state", "<0>")
		.Property("entrypoint-offset", "<0x00002000>")
		.Property("xlat-granule", "<0>")
		.Property("boot-order", "<0>")
		.Property("ns-interrupts-action", "<1>")
		.StartChild("services")
			.Compatible({ "arm,ffa-manifest-services"})
			.StartChild("service0")
				.Property("messaging-method", "<4>")
				.StringProperty("uuid", "b4b5671e-4a90-4fe1-b81f-fb13dae1dacb")
			.EndChild()
			.StartChild("service1")
				.StringProperty("uuid", "b4b5671e-4a90-4fe1-b81f-fb13dae1daaa")
				.Property("messaging-method", "<4>")
			.EndChild()
		.EndChild()
		.Build();
	/* clang-format on */
	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb), MANIFEST_SUCCESS);

	vm = &m->vm[0];
	ASSERT_EQ(vm->partition.ffa_version, 0x10002);
	ASSERT_THAT(
		std::span(vm->partition.services[0].uuid.uuid, 4),
		ElementsAre(0xb4b5671e, 0x4a904fe1, 0xb81ffb13, 0xdae1dacb));
	ASSERT_EQ(vm->partition.services[0].messaging_method,
		  FFA_PARTITION_INDIRECT_MSG);
	ASSERT_THAT(
		std::span(vm->partition.services[1].uuid.uuid, 4),
		ElementsAre(0xb4b5671e, 0x4a904fe1, 0xb81ffb13, 0xdae1daaa));
	ASSERT_EQ(vm->partition.services[1].messaging_method,
		  FFA_PARTITION_INDIRECT_MSG);
	ASSERT_EQ(vm->partition.service_count, 2);
	ASSERT_EQ(vm->partition.execution_ctx_count, 1);
	ASSERT_EQ(vm->partition.run_time_el, S_EL1);
	ASSERT_EQ(vm->partition.execution_state, AARCH64);
	ASSERT_EQ(vm->partition.ep_offset, 0x00002000);
	ASSERT_EQ(vm->partition.xlat_granule, PAGE_4KB);
	ASSERT_EQ(vm->partition.boot_order, 0);
	ASSERT_EQ(vm->partition.ns_interrupts_action, NS_ACTION_ME);
}

TEST_F(manifest, ffa_malformed_uuids)
{
	struct_manifest *m;

	/* Missing -. */
	/* clang-format off */
	std::vector<char>  dtb = ManifestDtBuilder()
		.Compatible({ "arm,ffa-manifest-1.1" })
		.Property("ffa-version", "<0x10002>")
		.Property("execution-ctx-count", "<1>")
		.Property("exception-level", "<2>")
		.Property("execution-state", "<0>")
		.Property("entrypoint-offset", "<0x00002000>")
		.Property("xlat-granule", "<0>")
		.Property("boot-order", "<0>")
		.Property("ns-interrupts-action", "<1>")
		.StartChild("services")
			.Compatible({ "arm,ffa-manifest-services"})
			.StartChild("service0")
				.Property("messaging-method", "<4>")
				.StringProperty("uuid", "b4b5671e4a90-4fe1-b81f-fb13dae1dacb")
			.EndChild()
		.EndChild()
		.Build();
	/* clang-format on */
	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb),
		  MANIFEST_ERROR_MALFORMED_UUID);

	/* . instead of -. */
	/* clang-format off */
	dtb = ManifestDtBuilder()
		.Compatible({ "arm,ffa-manifest-1.1" })
		.Property("ffa-version", "<0x10002>")
		.Property("execution-ctx-count", "<1>")
		.Property("exception-level", "<2>")
		.Property("execution-state", "<0>")
		.Property("entrypoint-offset", "<0x00002000>")
		.Property("xlat-granule", "<0>")
		.Property("boot-order", "<0>")
		.Property("ns-interrupts-action", "<1>")
		.StartChild("services")
			.Compatible({ "arm,ffa-manifest-services"})
			.StartChild("service0")
				.Property("messaging-method", "<4>")
				.StringProperty("uuid", "b4b5671e-4a90.4fe1-b81f-fb13dae1dacb")
			.EndChild()
		.EndChild()
		.Build();
	/* clang-format on */
	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb),
		  MANIFEST_ERROR_MALFORMED_UUID);

	/* Non hex character (z) used. */
	/* clang-format off */
	dtb = ManifestDtBuilder()
		.Compatible({ "arm,ffa-manifest-1.1" })
		.Property("ffa-version", "<0x10002>")
		.Property("execution-ctx-count", "<1>")
		.Property("exception-level", "<2>")
		.Property("execution-state", "<0>")
		.Property("entrypoint-offset", "<0x00002000>")
		.Property("xlat-granule", "<0>")
		.Property("boot-order", "<0>")
		.Property("ns-interrupts-action", "<1>")
		.StartChild("services")
			.Compatible({ "arm,ffa-manifest-services"})
			.StartChild("service0")
				.Property("messaging-method", "<4>")
				.StringProperty("uuid", "b4b5671e-4a90-4fe1-b81f-fb13dae1dacz")
			.EndChild()
		.EndChild()
		.Build();
	/* clang-format on */
	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb),
		  MANIFEST_ERROR_MALFORMED_UUID);
}

TEST_F(manifest, ffa_too_many_uuids)
{
	struct_manifest *m;

	/* clang-format off */
	std::vector<char>  dtb = ManifestDtBuilder()
		.Compatible({ "arm,ffa-manifest-1.1" })
		.Property("ffa-version", "<0x10002>")
		.Property("execution-ctx-count", "<1>")
		.Property("exception-level", "<2>")
		.Property("execution-state", "<0>")
		.Property("entrypoint-offset", "<0x00002000>")
		.Property("xlat-granule", "<0>")
		.Property("boot-order", "<0>")
		.Property("ns-interrupts-action", "<1>")
		.StartChild("services")
			.Compatible({ "arm,ffa-manifest-services"})
			.StartChild("service0")
				.Property("messaging-method", "<4>")
				.StringProperty("uuid", "b4b5671e-4a90-4fe1-b81f-fb13dae1dacb")
			.EndChild()
			.StartChild("service1")
				.Property("messaging-method", "<4>")
				.StringProperty("uuid", "b4b5671e-4a90-4fe1-b81f-fb13dae1daaa")
			.EndChild()
			.StartChild("service2")
				.Property("messaging-method", "<4>")
				.StringProperty("uuid", "b4b5671e-4a90-4fe1-b81f-fb13dae1daab")
			.EndChild()
			.StartChild("service3")
				.Property("messaging-method", "<4>")
				.StringProperty("uuid", "b4b5671e-4a90-4fe1-b81f-fb13dae1daac")
			.EndChild()
			.StartChild("service4")
				.Property("messaging-method", "<4>")
				.StringProperty("uuid", "b4b5671e-4a90-4fe1-b81f-fb13dae1daad")
			.EndChild()

		.EndChild()
		.Build();
	/* clang-format on */
	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb),
		  MANIFEST_ERROR_TOO_MANY_UUIDS);
}

TEST_F(manifest, ffa_uuid_all_zeros)
{
	struct_manifest *m;

	/* clang-format off */
	std::vector<char>  dtb = ManifestDtBuilder()
		.Compatible({ "arm,ffa-manifest-1.1" })
		.Property("ffa-version", "<0x10002>")
		.Property("execution-ctx-count", "<1>")
		.Property("exception-level", "<2>")
		.Property("execution-state", "<0>")
		.Property("entrypoint-offset", "<0x00002000>")
		.Property("xlat-granule", "<0>")
		.Property("boot-order", "<0>")
		.Property("ns-interrupts-action", "<1>")
		.StartChild("services")
			.Compatible({ "arm,ffa-manifest-services"})
			.StartChild("service0")
				.Property("messaging-method", "<4>")
				.StringProperty("uuid", "00000000-0000-0000-0000-000000000000")
			.EndChild()
		.EndChild()
		.Build();

	/* clang-format on */
	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb),
		  MANIFEST_ERROR_UUID_ALL_ZEROS);
}

TEST_F(manifest, ffa_valid_multiple_uuids_different_messaging_methods)
{
	struct manifest_vm *vm;
	struct_manifest *m;

	/* clang-format off */
	std::vector<char>  dtb = ManifestDtBuilder()
		.Compatible({ "arm,ffa-manifest-1.1" })
		.Property("ffa-version", "<0x10002>")
		.Property("execution-ctx-count", "<1>")
		.Property("exception-level", "<2>")
		.Property("execution-state", "<0>")
		.Property("entrypoint-offset", "<0x00002000>")
		.Property("xlat-granule", "<0>")
		.Property("boot-order", "<0>")
		.Property("ns-interrupts-action", "<1>")
		.StartChild("services")
			.Compatible({ "arm,ffa-manifest-services"})
			.StartChild("service0")
				.Property("messaging-method", "<4>")
				.StringProperty("uuid", "b4b5671e-4a90-4fe1-b81f-fb13dae1dacb")
			.EndChild()
			.StartChild("service1")
				.Property("messaging-method", "<6>")
				.StringProperty("uuid", "b4b5671e-4a90-4fe1-b81f-fb13dae1daaa")
			.EndChild()
		.EndChild()
		.Build();
	/* clang-format on */
	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb), MANIFEST_SUCCESS);

	vm = &m->vm[0];
	ASSERT_EQ(vm->partition.ffa_version, 0x10002);
	ASSERT_THAT(
		std::span(vm->partition.services[0].uuid.uuid, 4),
		ElementsAre(0xb4b5671e, 0x4a904fe1, 0xb81ffb13, 0xdae1dacb));
	ASSERT_EQ(vm->partition.services[0].messaging_method,
		  FFA_PARTITION_INDIRECT_MSG);
	ASSERT_THAT(
		std::span(vm->partition.services[1].uuid.uuid, 4),
		ElementsAre(0xb4b5671e, 0x4a904fe1, 0xb81ffb13, 0xdae1daaa));
	ASSERT_EQ(vm->partition.services[1].messaging_method,
		  FFA_PARTITION_INDIRECT_MSG | FFA_PARTITION_DIRECT_REQ_SEND);
	ASSERT_EQ(vm->partition.service_count, 2);
	ASSERT_EQ(vm->partition.execution_ctx_count, 1);
	ASSERT_EQ(vm->partition.run_time_el, S_EL1);
	ASSERT_EQ(vm->partition.execution_state, AARCH64);
	ASSERT_EQ(vm->partition.ep_offset, 0x00002000);
	ASSERT_EQ(vm->partition.xlat_granule, PAGE_4KB);
	ASSERT_EQ(vm->partition.boot_order, 0);
	ASSERT_EQ(vm->partition.ns_interrupts_action, NS_ACTION_ME);
}

TEST_F(manifest, ffa_multiple_uuids_unmatched_messaging_methods)
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

TEST_F(manifest, ffa_invalid_messaging_method)
{
	struct_manifest *m;

	/* clang-format off */
	std::vector<char>  dtb = ManifestDtBuilder()
		.Compatible({ "arm,ffa-manifest-1.1" })
		.Property("ffa-version", "<0x10002>")
		.Property("execution-ctx-count", "<1>")
		.Property("exception-level", "<2>")
		.Property("execution-state", "<0>")
		.Property("entrypoint-offset", "<0x00002000>")
		.Property("xlat-granule", "<0>")
		.Property("boot-order", "<0>")
		.Property("ns-interrupts-action", "<1>")
		.StartChild("services")
			.Compatible({ "arm,ffa-manifest-services"})
			.StartChild("service0")
				.Property("messaging-method", "<0>")
				.StringProperty("uuid", "b4b5671e-4a90-4fe1-b81f-fb13dae1dacb")
			.EndChild()
		.EndChild()
		.Build();
	/* clang-format on */
	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb),
		  MANIFEST_ERROR_INVALID_MESSAGING_METHOD);
	manifest_dealloc();

	/* Incompatible messaging method - unrecognized messaging-method. */
	/* clang-format off */
	dtb = ManifestDtBuilder()
		.Compatible({ "arm,ffa-manifest-1.1" })
		.Property("ffa-version", "<0x10002>")
		.Property("execution-ctx-count", "<1>")
		.Property("exception-level", "<2>")
		.Property("execution-state", "<0>")
		.Property("entrypoint-offset", "<0x00002000>")
		.Property("xlat-granule", "<0>")
		.Property("boot-order", "<0>")
		.Property("ns-interrupts-action", "<1>")
		.StartChild("services")
			.Compatible({ "arm,ffa-manifest-services"})
			.StartChild("service0")
				.Property("messaging-method", "<0x272>")
				.StringProperty("uuid", "b4b5671e-4a90-4fe1-b81f-fb13dae1dacb")
			.EndChild()
		.EndChild()
		.Build();
	/* clang-format on */
	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb),
		  MANIFEST_ERROR_INVALID_MESSAGING_METHOD);
}

/*
 * Test that the address space of two device region nodes specified across
 * different SPs cannot overlap.
 */
TEST_F(manifest, ffa_device_region_multi_sps)
{
	struct_manifest *m;
	struct memiter it;
	struct mm_stage1_locked mm_stage1_locked = mm_lock_stage1();
	struct boot_params params;
	Partition_package spkg_1;
	Partition_package spkg_2;

	/* clang-format off */
	std::vector<char>  dtb1 = ManifestDtBuilder()
		.Compatible({ "arm,ffa-manifest-1.1" })
		.Property("ffa-version", "<0x10001>")
		.FfaLoadAddress((uint64_t)&spkg_1)
		.Property("execution-ctx-count", "<1>")
		.Property("exception-level", "<0>")
		.Property("execution-state", "<0>")
		.Property("entrypoint-offset", "<0x0>")
		.Property("xlat-granule", "<0>")
		.StartChild("services")
			.Compatible({ "arm,ffa-manifest-services"})
			.StartChild("service0")
				.Property("messaging-method", "<0x7>")
				.StringProperty("uuid", "b4b5671e-4a90-4fe1-b81f-fb13dae1dacb")
			.EndChild()
		.EndChild()
		.StartChild("device-regions")
			.Compatible({ "arm,ffa-manifest-device-regions" })
			.StartChild("test-device-0")
				.Description("test-device-0")
				.Property("base-address", "<0x24000000>")
				.Property("pages-count", "<16>")
				.Property("attributes", "<3>")
			.EndChild()
		.EndChild()
		.Build();

	std::vector<char> dtb2 = ManifestDtBuilder()
		.Compatible({ "arm,ffa-manifest-1.1" })
		.Property("ffa-version", "<0x10001>")
		.FfaLoadAddress((uint64_t)&spkg_2)
		.Property("execution-ctx-count", "<1>")
		.Property("exception-level", "<0>")
		.Property("execution-state", "<0>")
		.Property("entrypoint-offset", "<0x0>")
		.Property("xlat-granule", "<0>")
		.StartChild("services")
			.Compatible({ "arm,ffa-manifest-services"})
			.StartChild("service0")
				.Property("messaging-method", "<0x7>")
				.StringProperty("uuid", "b4b5671e-4a90-4fe1-b81f-fb13dae1daaa")
			.EndChild()
		.EndChild()
		.StartChild("device-regions")
			.Compatible({ "arm,ffa-manifest-device-regions" })
			.StartChild("test-device-0")
				.Description("test-device-1")
				.Property("base-address", "<0x24000000>")
				.Property("pages-count", "<16>")
				.Property("attributes", "<3>")
			.EndChild()
		.EndChild()
		.Build();

	/* clang-format on */
	spkg_1.init(dtb1);
	spkg_2.init(dtb2);

	/* clang-format off */
	std::vector<char> core_dtb = ManifestDtBuilder()
		.StartChild("hypervisor")
			.Compatible()
			.StartChild("vm1")
				.DebugName("ffa_partition_1")
				.FfaPartition()
				.LoadAddress((uint64_t)&spkg_1)
				.VcpuCount(1)
				.MemSize(0x4000)
			.EndChild()
			.StartChild("vm2")
				.DebugName("ffa_partition_2")
				.FfaPartition()
				.LoadAddress((uint64_t)&spkg_2)
				.VcpuCount(1)
				.MemSize(0x4000)
			.EndChild()
		.EndChild()
		.Build();
	/* clang-format on */
	boot_params_init(&params, &spkg_1);
	memiter_init(&it, core_dtb.data(), core_dtb.size());
	ASSERT_EQ(manifest_init(mm_stage1_locked, &m, &it, &params),
		  MANIFEST_ERROR_MEM_REGION_OVERLAP);

	manifest_dealloc();

	/* clang-format off */
	dtb1 = ManifestDtBuilder()
		.Compatible({ "arm,ffa-manifest-1.1" })
		.Property("ffa-version", "<0x10001>")
		.FfaLoadAddress((uint64_t)&spkg_1)
		.Property("execution-ctx-count", "<1>")
		.Property("exception-level", "<0>")
		.Property("execution-state", "<0>")
		.Property("entrypoint-offset", "<0x0>")
		.Property("xlat-granule", "<0>")
		.StartChild("services")
			.Compatible({ "arm,ffa-manifest-services"})
			.StartChild("service0")
				.Property("messaging-method", "<0x7>")
				.StringProperty("uuid", "b4b5671e-4a90-4fe1-b81f-fb13dae1dacb")
			.EndChild()
		.EndChild()
		.StartChild("device-regions")
			.Compatible({ "arm,ffa-manifest-device-regions" })
			.StartChild("test-device-0")
				.Description("test-device-0")
				.Property("base-address", "<0x24000000>")
				.Property("pages-count", "<16>")
				.Property("attributes", "<3>")
			.EndChild()
		.EndChild()
		.Build();

	dtb2 = ManifestDtBuilder()
		.Compatible({ "arm,ffa-manifest-1.1" })
		.Property("ffa-version", "<0x10001>")
		.FfaLoadAddress((uint64_t)&spkg_2)
		.Property("execution-ctx-count", "<1>")
		.Property("exception-level", "<0>")
		.Property("execution-state", "<0>")
		.Property("entrypoint-offset", "<0x0>")
		.Property("xlat-granule", "<0>")
		.StartChild("services")
			.Compatible({ "arm,ffa-manifest-services"})
			.StartChild("service0")
				.Property("messaging-method", "<0x7>")
				.StringProperty("uuid", "b4b5671e-4a90-4fe1-b81f-fb13dae1daaa")
			.EndChild()
		.EndChild()
		.StartChild("device-regions")
			.Compatible({ "arm,ffa-manifest-device-regions" })
			.StartChild("test-device-0")
				.Description("test-device-1")
				.Property("base-address", "<0x25000000>")
				.Property("pages-count", "<16>")
				.Property("attributes", "<3>")
			.EndChild()
		.EndChild()
		.Build();

	/* clang-format on */
	spkg_1.init(dtb1);
	spkg_2.init(dtb2);

	/* clang-format off */
	core_dtb = ManifestDtBuilder()
		.StartChild("hypervisor")
			.Compatible()
			.StartChild("vm1")
				.DebugName("ffa_partition_1")
				.FfaPartition()
				.LoadAddress((uint64_t)&spkg_1)
				.VcpuCount(1)
				.MemSize(0x4000)
			.EndChild()
			.StartChild("vm2")
				.DebugName("ffa_partition_2")
				.FfaPartition()
				.LoadAddress((uint64_t)&spkg_2)
				.VcpuCount(1)
				.MemSize(0x4000)
			.EndChild()
		.EndChild()
		.Build();
	/* clang-format on */
	boot_params_init(&params, &spkg_1);
	memiter_init(&it, core_dtb.data(), core_dtb.size());
	ASSERT_EQ(manifest_init(mm_stage1_locked, &m, &it, &params),
		  MANIFEST_SUCCESS);

	mm_unlock_stage1(&mm_stage1_locked);
}

/*
 * Tests to trigger various error conditions while parsing dma related
 * properties of memory region nodes.
 */
TEST_F(manifest, ffa_memory_region_invalid_dma_properties)
{
	struct_manifest *m;

	/*
	 * SMMU ID must be specified if the partition specifies Stream IDs for
	 * any device upstream of SMMU.
	 */
	/* clang-format off */
	std::vector<char> dtb = ManifestDtBuilder()
		.FfaValidManifest()
		.StartChild("memory-regions")
			.Compatible({ "arm,ffa-manifest-memory-regions" })
			.StartChild("test-memory")
				.Description("test-memory")
				.Property("base-address", "<0x7100000>")
				.Property("pages-count", "<16>")
				.Property("attributes", "<3>")
				.Property("stream-ids", "<0 1>")
				.Property("interrupts", "<2 3>, <4 5>")
			.EndChild()
		.EndChild()
		.Build();
	/* clang-format on */

	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb),
		  MANIFEST_ERROR_MISSING_SMMU_ID);
	manifest_dealloc();

	/*
	 * All stream ids belonging to a dma device must specify the same access
	 * permissions.
	 */
	/* clang-format off */
	dtb = ManifestDtBuilder()
		.FfaValidManifest()
		.StartChild("memory-regions")
			.Compatible({ "arm,ffa-manifest-memory-regions" })
			.StartChild("test-memory")
				.Description("test-memory")
				.Property("base-address", "<0x7100000>")
				.Property("pages-count", "<16>")
				.Property("attributes", "<3>")
				.Property("smmu-id", "<1>")
				.Property("stream-ids", "<0 1>")
				.Property("stream-ids-access-permissions", "<0x3 0xb>")
				.Property("interrupts", "<2 3>, <4 5>")
			.EndChild()
		.EndChild()
		.Build();
	/* clang-format on */

	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb),
		  MANIFEST_ERROR_MISMATCH_DMA_ACCESS_PERMISSIONS);
	manifest_dealloc();

	/*
	 * DMA device stream ID count exceeds predefined limit.
	 */
	/* clang-format off */
	dtb = ManifestDtBuilder()
		.FfaValidManifest()
		.StartChild("memory-regions")
			.Compatible({ "arm,ffa-manifest-memory-regions" })
			.StartChild("test-memory")
				.Description("test-memory")
				.Property("base-address", "<0x7100000>")
				.Property("pages-count", "<16>")
				.Property("attributes", "<3>")
				.Property("smmu-id", "<1>")
				.Property("stream-ids", "<0 1 4 9 12 >")
				.Property("stream-ids-access-permissions", "<0x3 0x3 0x3>")
			.EndChild()
		.EndChild()
		.Build();
	/* clang-format on */

	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb),
		  MANIFEST_ERROR_STREAM_IDS_OVERFLOW);
	manifest_dealloc();

	/*
	 * DMA access permissions count exceeds predefined limit
	 */
	/* clang-format off */
	dtb = ManifestDtBuilder()
		.FfaValidManifest()
		.StartChild("memory-regions")
			.Compatible({ "arm,ffa-manifest-memory-regions" })
			.StartChild("test-memory")
				.Description("test-memory")
				.Property("base-address", "<0x7100000>")
				.Property("pages-count", "<16>")
				.Property("attributes", "<3>")
				.Property("smmu-id", "<1>")
				.Property("stream-ids", "<0 1>")
				.Property("stream-ids-access-permissions", "<0x3 0x3 0x3 0x3 0x3>")
			.EndChild()
		.EndChild()
		.Build();
	/* clang-format on */

	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb),
		  MANIFEST_ERROR_DMA_ACCESS_PERMISSIONS_OVERFLOW);
}

/*
 * Tests to trigger various error conditions while parsing dma related
 * properties of device region nodes.
 */
TEST_F(manifest, ffa_device_region_invalid_dma_properties)
{
	struct_manifest *m;

	/*
	 * SMMU ID must be specified if the partition specifies Stream IDs for
	 * any device upstream of SMMU.
	 */
	/* clang-format off */
	std::vector<char> dtb = ManifestDtBuilder()
		.FfaValidManifest()
		.StartChild("device-regions")
			.Compatible({ "arm,ffa-manifest-device-regions" })
			.StartChild("test-device")
				.Description("test-device")
				.Property("base-address", "<0x24000000>")
				.Property("pages-count", "<16>")
				.Property("attributes", "<3>")
				.Property("stream-ids", "<0 1>")
				.Property("interrupts", "<2 3>, <4 5>")
			.EndChild()
		.EndChild()
		.Build();
	/* clang-format on */

	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb),
		  MANIFEST_ERROR_MISSING_SMMU_ID);
	manifest_dealloc();

	/*
	 *  Dma devices defined through device region nodes exceed predefined
	 * limit.
	 */
	/* clang-format off */
	dtb = ManifestDtBuilder()
		.FfaValidManifest()
		.StartChild("device-regions")
			.Compatible({ "arm,ffa-manifest-device-regions" })
			.StartChild("test-device-0")
				.Description("test-device-0")
				.Property("base-address", "<0x27000000>")
				.Property("pages-count", "<16>")
				.Property("attributes", "<3>")
				.Property("smmu-id", "<1>")
				.Property("stream-ids", "<0 1>")
			.EndChild()
			.StartChild("test-device-1")
				.Description("test-device-1")
				.Property("base-address", "<0x25000000>")
				.Property("pages-count", "<16>")
				.Property("attributes", "<3>")
				.Property("smmu-id", "<1>")
				.Property("stream-ids", "<2 3>")
			.EndChild()
			.StartChild("test-device-2")
				.Description("test-device-2")
				.Property("base-address", "<0x26000000>")
				.Property("pages-count", "<16>")
				.Property("attributes", "<3>")
				.Property("smmu-id", "<1>")
				.Property("stream-ids", "<4 5>")
			.EndChild()
		.EndChild()
		.Build();
	/* clang-format on */

	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb),
		  MANIFEST_ERROR_DMA_DEVICE_OVERFLOW);
}

TEST_F(manifest, validate_sp_lifecycle_support)
{
	struct_manifest *m;
	std::vector<char> dtb;

	/* Lifecycle support only allowed for UP SP. */
	/* clang-format off */
	dtb = ManifestDtBuilder()
		.Compatible({ "arm,ffa-manifest-1.1" })
		.Property("ffa-version", "<0x10002>")
		.Property("execution-ctx-count", "<1>")
		.Property("exception-level", "<2>")
		.Property("execution-state", "<0>")
		.Property("entrypoint-offset", "<0x00002000>")
		.BooleanProperty("lifecycle-support")
		.StartChild("services")
			.Compatible({ "arm,ffa-manifest-services"})
			.StartChild("service0")
				.Property("messaging-method", "<1>")
				.StringProperty("uuid", "b4b5671e-4a90-4fe1-b81f-fb13dae1dacb")
			.EndChild()
		.EndChild()
		.Build();
	/* clang-format on */

	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb), MANIFEST_SUCCESS);
	manifest_dealloc();

	/* Lifecycle support not allowed for MP SP. */
	/* clang-format off */
	dtb = ManifestDtBuilder()
		.Compatible({ "arm,ffa-manifest-1.1" })
		.Property("ffa-version", "<0x10002>")
		.Property("execution-ctx-count", "<8>")
		.Property("exception-level", "<2>")
		.Property("execution-state", "<0>")
		.Property("entrypoint-offset", "<0x00002000>")
		.BooleanProperty("lifecycle-support")
		.StartChild("services")
			.Compatible({ "arm,ffa-manifest-services"})
			.StartChild("service0")
				.Property("messaging-method", "<1>")
				.StringProperty("uuid", "b4b5671e-4a90-4fe1-b81f-fb13dae1dacb")
			.EndChild()
		.EndChild()
		.Build();
	/* clang-format on */

	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb),
		  MANIFEST_ERROR_ILLEGAL_LIFECYCLE_SUPPORT);
	manifest_dealloc();
}

TEST_F(manifest, validate_sp_abort_actions)
{
	struct_manifest *m;
	std::vector<char> dtb;

	/*
	 * Abort action can only be specified if lifecycle support is
	 * enabled.
	 */
	/* clang-format off */
	dtb = ManifestDtBuilder()
		.FfaValidManifest()
		.Property("abort-action", "<0>")
		.Build();
	/* clang-format on */

	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb),
		  MANIFEST_ERROR_ILLEGAL_ABORT_ACTION);
	manifest_dealloc();

	/* clang-format off */
	dtb = ManifestDtBuilder()
		.FfaValidManifest()
		.BooleanProperty("lifecycle-support")
		.Property("abort-action", "<0>")
		.Build();
	/* clang-format on */

	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb), MANIFEST_SUCCESS);
	manifest_dealloc();

	/* clang-format off */
	dtb = ManifestDtBuilder()
		.FfaValidManifest()
		.BooleanProperty("lifecycle-support")
		.Property("abort-action", "<1>")
		.Build();
	/* clang-format on */

	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb), MANIFEST_SUCCESS);
	manifest_dealloc();

	/* clang-format off */
	dtb = ManifestDtBuilder()
		.FfaValidManifest()
		.BooleanProperty("lifecycle-support")
		.Property("abort-action", "<2>")
		.Build();
	/* clang-format on */

	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb), MANIFEST_SUCCESS);
	manifest_dealloc();

	/* clang-format off */
	dtb = ManifestDtBuilder()
		.FfaValidManifest()
		.BooleanProperty("lifecycle-support")
		.Property("abort-action", "<3>")
		.Build();
	/* clang-format on */

	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb), MANIFEST_SUCCESS);
	manifest_dealloc();

	/* clang-format off */
	dtb = ManifestDtBuilder()
		.FfaValidManifest()
		.BooleanProperty("lifecycle-support")
		.Property("abort-action", "<0x4>")
		.Build();
	/* clang-format on */

	ASSERT_EQ(ffa_manifest_from_vec(&m, dtb),
		  MANIFEST_ERROR_ILLEGAL_ABORT_ACTION);
	manifest_dealloc();
}

} /* namespace */
