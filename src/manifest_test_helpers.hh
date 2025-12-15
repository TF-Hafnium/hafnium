/*
 * Copyright 2026 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include <algorithm>
#include <array>
#include <cstdlib>
#include <format>
#include <gmock/gmock.h>
#include <iostream>
#include <iterator>
#include <sstream>
#include <string_view>
#include <vector>
#include <unistd.h>

extern "C" {
#include "hf/arch/std.h"
#include "hf/boot_params.h"
#include "hf/manifest.h"
#include "hf/mm.h"
#include "hf/plat/memory_alloc.h"
#include "hf/sp_pkg.h"
}

namespace manifest_test
{
using struct_manifest = struct manifest;

template <typename T>
void exec(const char *program, const char *args[], const T &stdin,
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
		execv(program, const_cast<char *const *>(args));
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
 *
 * For each node we record it's properties and it's children
 * separately so when building the dts we can ensure we always
 * meet the condition that all properties precede subnodes
 * regardless of the command order to the ManifestDtBuilder.
 */
class ManifestDtBuilder
{
       private:
	/*
	 * Name: The name of the node.
	 * child_label: If the child we're about to populate with properties
	 * has a label record it here.
	 * properties: Holds the properties at that level of the dts.
	 * children: Holds the properties of the children below.
	 */
	struct Node {
		std::string name;
		std::string_view child_label;
		std::ostringstream properties;
		std::ostringstream children;
	};

	std::vector<Node> stack_;
	std::stringstream dts_;

       public:
	ManifestDtBuilder()
	{
		dts_ << "/dts-v1/;" << std::endl;
		dts_ << std::endl;

		/* Start root node. */
		StartChild("/");
	}

	std::vector<char> Build(bool dump = false)
	{
		const char *program = "./build/image/dtc.py";
		const char *dtc_args[] = {program, "compile", NULL};
		std::vector<char> dtc_stdout;

		/* Finish root node. */
		while (stack_.size() > 1) {
			EndChild();
		}

		Node root = std::move(stack_.back());
		stack_.pop_back();

		dts_ << root.name << " {\n"
		     << root.properties.str() << root.children.str() << "};\n";

		if (dump) {
			Dump();
		}

		exec(program, dtc_args, dts_.str(), &dtc_stdout);
		return dtc_stdout;
	}

	void Dump()
	{
		std::cerr << dts_.str() << std::endl;
	}

	ManifestDtBuilder &StartChild(const std::string_view &name)
	{
		stack_.push_back(Node{std::string(name), std::string_view{},
				      std::ostringstream{},
				      std::ostringstream{}});
		return *this;
	}

	ManifestDtBuilder &EndChild()
	{
		/* Child must have a parent. */
		assert(stack_.size() > 1);

		Node child = std::move(stack_.back());
		stack_.pop_back();

		Node &parent = stack_.back();

		if (!parent.child_label.empty()) {
			parent.children << parent.child_label << ": ";
		}
		parent.children << child.name << " {\n"
				<< child.properties.str()
				<< child.children.str() << "};\n";

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

	ManifestDtBuilder &Description(const std::string_view &value)
	{
		return StringProperty("description", value);
	}

	ManifestDtBuilder &KernelFilename(const std::string_view &value)
	{
		return StringProperty("kernel_filename", value);
	}

	ManifestDtBuilder &RamdiskFilename(const std::string_view &value)
	{
		return StringProperty("ramdisk_filename", value);
	}

	ManifestDtBuilder &BootAddress(uint64_t value)
	{
		return Integer64Property("boot_address", value);
	}

	ManifestDtBuilder &VcpuCount(uint32_t value)
	{
		return IntegerProperty("vcpu_count", value);
	}

	ManifestDtBuilder &MemSize(uint32_t value)
	{
		return IntegerProperty("mem_size", value);
	}

	ManifestDtBuilder &SmcWhitelist(const std::vector<uint32_t> &value)
	{
		return IntegerListProperty("smc_whitelist", value);
	}

	ManifestDtBuilder &SmcWhitelistPermissive()
	{
		return BooleanProperty("smc_whitelist_permissive");
	}

	ManifestDtBuilder &LoadAddress(uint64_t value)
	{
		return Integer64Property("load_address", value, true);
	}

	ManifestDtBuilder &FfaPartition()
	{
		return BooleanProperty("is_ffa_partition");
	}

	ManifestDtBuilder &Property(const std::string_view &name,
				    const std::string_view &value)
	{
		Node &node = stack_.back();
		node.properties << name << " = " << value << ";" << std::endl;
		return *this;
	}

	ManifestDtBuilder &Label(const std::string_view &name)
	{
		Node &node = stack_.back();
		node.child_label = name;
		return *this;
	}

	ManifestDtBuilder &FfaValidManifest()
	{
		/* clang-format off */
		Compatible({"arm,ffa-manifest-1.1"});
		Property("ffa-version", "<0x10000>");
		Property("execution-ctx-count", "<1>");
		Property("exception-level", "<2>");
		Property("execution-state", "<0>");
		Property("entrypoint-offset", "<0x00002000>");
		Property("xlat-granule", "<0>");
		Property("boot-order", "<0>");
		Property("ns-interrupts-action", "<1>");
		StartChild("services");
			Compatible({ "arm,ffa-manifest-services"});
			StartChild("service0");
				Property("messaging-method", "<4>");
				StringProperty("uuid", "b4b5671e-4a90-4fe1-b81f-fb13dae1dacb");
			EndChild();
		EndChild();
		/* clang-format on */
		return *this;
	}

	ManifestDtBuilder &FfaLoadAddress(uint64_t value)
	{
		Integer64Property("load-address", value, true);
		return *this;
	}

	ManifestDtBuilder &StringProperty(const std::string_view &name,
					  const std::string_view &value)
	{
		Node &node = stack_.back();
		node.properties << name << " = \"" << value << "\";"
				<< std::endl;
		return *this;
	}

	ManifestDtBuilder &StringListProperty(
		const std::string_view &name,
		const std::vector<std::string_view> &value)
	{
		bool is_first = true;
		Node &node = stack_.back();

		node.properties << name << " = ";
		for (const std::string_view &entry : value) {
			if (is_first) {
				is_first = false;
			} else {
				node.properties << ", ";
			}
			node.properties << "\"" << entry << "\"";
		}
		node.properties << ";" << std::endl;
		return *this;
	}

	ManifestDtBuilder &IntegerProperty(const std::string_view &name,
					   uint32_t value, bool hex = false)
	{
		Node &node = stack_.back();
		std::ostream_iterator<char> out(node.properties);

		if (hex) {
			std::format_to(out, "{} = <{:#08x}>;\n", name, value);
		} else {
			std::format_to(out, "{} = <{}>;\n", name, value);
		}
		return *this;
	}

	ManifestDtBuilder &Integer64Property(const std::string_view &name,
					     uint64_t value, bool hex = false)
	{
		uint32_t high = value >> 32;
		uint32_t low = (uint32_t)value;
		Node &node = stack_.back();
		std::ostream_iterator<char> out(node.properties);

		if (hex) {
			std::format_to(out, "{} = <{:#08x} {:#08x}>;\n", name,
				       high, low);
		} else {
			std::format_to(out, "{} = <{} {}>;\n", name, high, low);
		}

		return *this;
	}

	ManifestDtBuilder &IntegerListProperty(
		const std::string_view &name,
		const std::vector<uint32_t> &value)
	{
		Node &node = stack_.back();
		node.properties << name << " = < ";
		for (const uint32_t entry : value) {
			node.properties << entry << " ";
		}
		node.properties << ">;" << std::endl;
		return *this;
	}

	ManifestDtBuilder &BooleanProperty(const std::string_view &name)
	{
		Node &node = stack_.back();
		node.properties << name << ";" << std::endl;
		return *this;
	}
};

class manifest : public ::testing::Test
{
	void SetUp() override
	{
	}

	void TearDown() override
	{
		manifest_dealloc();
	}

       protected:
	void manifest_dealloc(void)
	{
	}

       public:
	class Partition_package
	{
	       public:
		alignas(PAGE_SIZE) struct sp_pkg_header spkg;
		alignas(PAGE_SIZE) char manifest_dtb[PAGE_SIZE] = {};
		alignas(PAGE_SIZE) char img[PAGE_SIZE] = {};

		Partition_package(const std::vector<char> &vec)
		{
			init(vec);
		}

		Partition_package()
		{
		}

		void init(const std::vector<char> &vec)
		{
			/* Initialise header field. */
			spkg.magic = SP_PKG_HEADER_MAGIC;
			spkg.version = SP_PKG_HEADER_VERSION_2;
			spkg.pm_offset = PAGE_SIZE;
			spkg.pm_size = vec.size();
			spkg.img_offset = 2 * PAGE_SIZE;
			spkg.img_size = ARRAY_SIZE(img);

			/* Copy dtb into package. */
			std::copy(vec.begin(), vec.end(), manifest_dtb);
		}
	};

	static void boot_params_init(struct boot_params *params,
				     Partition_package *pkg)
	{
		/*
		 * For the manifest tests we only care about the memory ranges
		 * in boot_params.
		 */
		params->mem_ranges[0].begin = pa_init((uintpaddr_t)0x7000000);
		params->mem_ranges[0].end = pa_init((uintpaddr_t)0x8ffffff);
		params->mem_ranges_count = 1;

		if (pkg != nullptr) {
			auto mem_base = (uintpaddr_t)pkg;
			uintpaddr_t mem_end =
				mem_base + sp_pkg_get_mem_size(&pkg->spkg);

			params->mem_ranges_count++;

			params->mem_ranges[1].begin = pa_init(mem_base);
			params->mem_ranges[1].end = pa_init(mem_end);
		}

		params->ns_mem_ranges[0].begin =
			pa_init((uintpaddr_t)0x7000000);
		params->ns_mem_ranges[0].end = pa_init((uintpaddr_t)0x8ffffff);
		params->ns_mem_ranges_count = 1;

		params->ns_device_mem_ranges[0].begin =
			pa_init((uintpaddr_t)0x20000000);
		params->ns_device_mem_ranges[0].end =
			pa_init((uintpaddr_t)0x24000000);
		params->ns_device_mem_ranges_count = 1;

		params->device_mem_ranges[0].begin =
			pa_init((uintpaddr_t)0x24000000);
		params->device_mem_ranges[0].end =
			pa_init((uintpaddr_t)0x28000000);
		params->device_mem_ranges_count = 1;
	}

	static enum manifest_return_code manifest_from_vec(
		struct_manifest **m, const std::vector<char> &vec)
	{
		struct memiter it;
		struct mm_stage1_locked mm_stage1_locked = mm_lock_stage1();
		struct boot_params params;
		enum manifest_return_code ret;

		boot_params_init(&params, nullptr);

		memiter_init(&it, vec.data(), vec.size());

		ret = manifest_init(mm_stage1_locked, m, &it, &params);
		mm_unlock_stage1(&mm_stage1_locked);
		return ret;
	}

	static enum manifest_return_code ffa_manifest_from_spkg(
		struct_manifest **m, Partition_package *spkg)
	{
		struct memiter it;
		struct mm_stage1_locked mm_stage1_locked = mm_lock_stage1();
		struct boot_params params;
		enum manifest_return_code ret;

		boot_params_init(&params, spkg);

		/* clang-format off */
		std::vector<char> core_dtb = ManifestDtBuilder()
			.StartChild("hypervisor")
				.Compatible()
				.StartChild("vm1")
					.DebugName("primary_vm")
					.FfaPartition()
					.LoadAddress((uint64_t)spkg)
				.EndChild()
			.EndChild()
			.Build(true);
		/* clang-format on */
		memiter_init(&it, core_dtb.data(), core_dtb.size());

		ret = manifest_init(mm_stage1_locked, m, &it, &params);
		mm_unlock_stage1(&mm_stage1_locked);
		return ret;
	}

	static enum manifest_return_code ffa_manifest_from_vec(
		struct_manifest **m, const std::vector<char> &vec)
	{
		struct memiter it;
		struct mm_stage1_locked mm_stage1_locked = mm_lock_stage1();
		Partition_package spkg(vec);
		struct boot_params params;
		enum manifest_return_code ret;

		boot_params_init(&params, &spkg);

		/* clang-format off */
		std::vector<char> core_dtb = ManifestDtBuilder()
			.StartChild("hypervisor")
				.Compatible()
				.StartChild("vm1")
					.DebugName("primary_vm")
					.FfaPartition()
					.LoadAddress((uint64_t)&spkg)
				.EndChild()
			.EndChild()
			.Build();
		/* clang-format on */
		memiter_init(&it, core_dtb.data(), core_dtb.size());

		ret = manifest_init(mm_stage1_locked, m, &it, &params);
		mm_unlock_stage1(&mm_stage1_locked);
		return ret;
	}
};

class manifest_v1_0 : public manifest
{
};

} /* namespace manifest_test */
