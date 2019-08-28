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

#include <array>
#include <cstdio>
#include <sstream>

#include <gmock/gmock.h>

extern "C" {
#include "hf/manifest.h"
}

namespace
{
using ::testing::Eq;
using ::testing::NotNull;

template <typename T>
void exec(const char *program, char *const args[], const T &stdin,
	  std::vector<char> *stdout)
{
	/* Create two pipes, one for stdin and one for stdout. */
	int pipes[2][2];
	pipe(pipes[0]);
	pipe(pipes[1]);

	/* Assign FDs for reading/writing by the parent/child. */
	int parent_read_fd = pipes[1][0];  /* stdout pipe, read FD */
	int parent_write_fd = pipes[0][1]; /* stdin pipe, write FD */
	int child_read_fd = pipes[0][0];   /* stdin pipe, read FD */
	int child_write_fd = pipes[1][1];  /* stdout pipe, write FD */

	if (fork()) {
		/* Parent process. */
		std::array<char, 128> buf;
		ssize_t res;

		/* Close child FDs which won't be used. */
		close(child_read_fd);
		close(child_write_fd);

		/* Write to stdin. */
		for (size_t count = 0; count < stdin.size();) {
			res = write(parent_write_fd, stdin.data() + count,
				    stdin.size() - count);
			if (res < 0) {
				std::cerr << "IO error" << std::endl;
				exit(1);
			}
			count += res;
		}
		close(parent_write_fd);

		/* Read from stdout. */
		while (true) {
			res = read(parent_read_fd, buf.data(), buf.size());
			if (res == 0) {
				/* EOF */
				break;
			} else if (res < 0) {
				std::cerr << "IO error" << std::endl;
				exit(1);
			}
			stdout->insert(stdout->end(), buf.begin(),
				       buf.begin() + res);
		}
		close(parent_read_fd);
	} else {
		/* Child process. */

		/* Redirect stdin/stdout to read/write FDs. */
		dup2(child_read_fd, STDIN_FILENO);
		dup2(child_write_fd, STDOUT_FILENO);

		/* Close all FDs which are now unused. */
		close(child_read_fd);
		close(child_write_fd);
		close(parent_read_fd);
		close(parent_write_fd);

		/* Execute the given program. */
		execv(program, args);
	}
}

/**
 * Class for programatically building a Device Tree.
 *
 * Usage:
 *   std::vector<char> dtb = ManifestDtBuilder()
 *       .Command1()
 *       .Command2()
 *       ...
 *       .CommandN()
 *       .Build();
 */
class ManifestDtBuilder
{
       public:
	ManifestDtBuilder()
	{
		dts_ << "/dts-v1/;" << std::endl;
		dts_ << std::endl;

		/* Start root node. */
		StartChild("/");
	}

	std::vector<char> Build()
	{
		char *const dtc_args[] = {NULL};
		std::vector<char> dtc_stdout;

		/* Finish root node. */
		EndChild();

		exec("./build/image/dtc.py", dtc_args, dts_.str(), &dtc_stdout);
		return dtc_stdout;
	}

	ManifestDtBuilder &StartChild(const std::string_view &name)
	{
		dts_ << name << " {" << std::endl;
		return *this;
	}

	ManifestDtBuilder &EndChild()
	{
		dts_ << "};" << std::endl;
		return *this;
	}

	ManifestDtBuilder &Compatible(const std::vector<std::string_view>
					      &value = {"hafnium,hafnium"})
	{
		return StringListProperty("compatible", value);
	}

	ManifestDtBuilder &DebugName(const std::string_view &value)
	{
		return StringProperty("debug_name", value);
	}

	ManifestDtBuilder &KernelFilename(const std::string_view &value)
	{
		return StringProperty("kernel_filename", value);
	}

	ManifestDtBuilder &VcpuCount(uint64_t value)
	{
		return IntegerProperty("vcpu_count", value);
	}

	ManifestDtBuilder &MemSize(uint64_t value)
	{
		return IntegerProperty("mem_size", value);
	}

       private:
	ManifestDtBuilder &StringProperty(const std::string_view &name,
					  const std::string_view &value)
	{
		dts_ << name << " = \"" << value << "\";" << std::endl;
		return *this;
	}

	ManifestDtBuilder &StringListProperty(
		const std::string_view &name,
		const std::vector<std::string_view> &value)
	{
		bool is_first = true;

		dts_ << name << " = ";
		for (const std::string_view &entry : value) {
			if (is_first) {
				is_first = false;
			} else {
				dts_ << ", ";
			}
			dts_ << "\"" << entry << "\"";
		}
		dts_ << ";" << std::endl;
		return *this;
	}

	ManifestDtBuilder &IntegerProperty(const std::string_view &name,
					   uint64_t value)
	{
		dts_ << name << " = <" << value << ">;" << std::endl;
		return *this;
	}

	std::stringstream dts_;
};

TEST(manifest, no_hypervisor_node)
{
	struct manifest m;
	struct memiter it;
	std::vector<char> dtb = ManifestDtBuilder().Build();

	memiter_init(&it, dtb.data(), dtb.size());
	ASSERT_EQ(manifest_init(&m, &it),
		  MANIFEST_ERROR_NO_HYPERVISOR_FDT_NODE);
}

TEST(manifest, no_compatible_property)
{
	struct manifest m;
	struct memiter it;

	/* clang-format off */
	std::vector<char> dtb = ManifestDtBuilder()
		.StartChild("hypervisor")
		.EndChild()
		.Build();
	/* clang-format on */

	memiter_init(&it, dtb.data(), dtb.size());
	ASSERT_EQ(manifest_init(&m, &it), MANIFEST_ERROR_PROPERTY_NOT_FOUND);
}

TEST(manifest, not_compatible)
{
	struct manifest m;
	struct memiter it;

	/* clang-format off */
	std::vector<char> dtb = ManifestDtBuilder()
		.StartChild("hypervisor")
			.Compatible({ "foo,bar" })
		.EndChild()
		.Build();
	/* clang-format on */

	memiter_init(&it, dtb.data(), dtb.size());
	ASSERT_EQ(manifest_init(&m, &it), MANIFEST_ERROR_NOT_COMPATIBLE);
}

TEST(manifest, compatible_one_of_many)
{
	struct manifest m;
	struct memiter it;

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

	memiter_init(&it, dtb.data(), dtb.size());
	ASSERT_EQ(manifest_init(&m, &it), MANIFEST_SUCCESS);
}

TEST(manifest, no_vm_nodes)
{
	struct manifest m;
	struct memiter it;

	/* clang-format off */
	std::vector<char> dtb = ManifestDtBuilder()
		.StartChild("hypervisor")
			.Compatible()
		.EndChild()
		.Build();
	/* clang-format on */

	memiter_init(&it, dtb.data(), dtb.size());
	ASSERT_EQ(manifest_init(&m, &it), MANIFEST_ERROR_NO_PRIMARY_VM);
}

TEST(manifest, reserved_vm_id)
{
	struct manifest m;
	struct memiter it;

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

	memiter_init(&it, dtb.data(), dtb.size());
	ASSERT_EQ(manifest_init(&m, &it), MANIFEST_ERROR_RESERVED_VM_ID);
}

static std::vector<char> gen_vcpu_count_limit_dtb(uint64_t vcpu_count)
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

TEST(manifest, vcpu_count_limit)
{
	struct manifest m;
	struct memiter it;
	std::vector<char> dtb_last_valid = gen_vcpu_count_limit_dtb(UINT16_MAX);
	std::vector<char> dtb_first_invalid =
		gen_vcpu_count_limit_dtb(UINT16_MAX + 1);

	memiter_init(&it, dtb_last_valid.data(), dtb_last_valid.size());
	ASSERT_EQ(manifest_init(&m, &it), MANIFEST_SUCCESS);
	ASSERT_EQ(m.num_vms, 2);
	ASSERT_EQ(m.vm[1].secondary.vcpu_count, UINT16_MAX);

	memiter_init(&it, dtb_first_invalid.data(), dtb_first_invalid.size());
	ASSERT_EQ(manifest_init(&m, &it), MANIFEST_ERROR_INTEGER_OVERFLOW);
}

TEST(manifest, valid)
{
	struct manifest m;
	struct manifest_vm *vm;
	struct memiter it;

	/* clang-format off */
	std::vector<char> dtb = ManifestDtBuilder()
		.StartChild("hypervisor")
			.Compatible()
			.StartChild("vm1")
				.DebugName("primary_vm")
			.EndChild()
			.StartChild("vm3")
				.DebugName("second_secondary_vm")
				.VcpuCount(43)
				.MemSize(0x12345)
				.KernelFilename("second_kernel")
			.EndChild()
			.StartChild("vm2")
				.DebugName("first_secondary_vm")
				.VcpuCount(42)
				.MemSize(12345)
				.KernelFilename("first_kernel")
			.EndChild()
		.EndChild()
		.Build();
	/* clang-format on */

	memiter_init(&it, dtb.data(), dtb.size());

	ASSERT_EQ(manifest_init(&m, &it), MANIFEST_SUCCESS);
	ASSERT_EQ(m.num_vms, 3);

	vm = &m.vm[0];
	ASSERT_TRUE(memiter_iseq(&vm->debug_name, "primary_vm"));

	vm = &m.vm[1];
	ASSERT_TRUE(memiter_iseq(&vm->debug_name, "first_secondary_vm"));
	ASSERT_EQ(vm->secondary.vcpu_count, 42);
	ASSERT_EQ(vm->secondary.mem_size, 12345);
	ASSERT_TRUE(
		memiter_iseq(&vm->secondary.kernel_filename, "first_kernel"));

	vm = &m.vm[2];
	ASSERT_TRUE(memiter_iseq(&vm->debug_name, "second_secondary_vm"));
	ASSERT_EQ(vm->secondary.vcpu_count, 43);
	ASSERT_EQ(vm->secondary.mem_size, 0x12345);
	ASSERT_TRUE(
		memiter_iseq(&vm->secondary.kernel_filename, "second_kernel"));
}

} /* namespace */
