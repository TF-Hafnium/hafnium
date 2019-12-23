#!/usr/bin/env python3
#
# Copyright 2019 The Hafnium Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Check ELF file for assembly-level regressions.

Objdumps the given ELF file and detects known assembly patterns, checking for
regressions on bugs such as CPU erratas. Throws an exception if a broken pattern
is detected.
"""

import argparse
import os
import re
import subprocess
import sys

HF_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
CLANG_ROOT = os.path.join(HF_ROOT, "prebuilts", "linux-x64", "clang")
OBJDUMP = os.path.join(CLANG_ROOT, "bin", "llvm-objdump")

def check_eret_speculation_barrier(objdump_stdout):
	"""
	Some ARM64 CPUs speculatively execute instructions after ERET.
	Check that every ERET is followed by DSB NSH and ISB.
	"""
	found_eret = False

	STATE_DEFAULT = 1
	STATE_EXPECT_DSB_NSH = 2
	STATE_EXPECT_ISB = 3

	REGEX_ERET = re.compile(r"^\s*[0-9a-f]+:\s*e0 03 9f d6\s+eret$")
	REGEX_DSB_NSH = re.compile(r"^\s*[0-9a-f]+:\s*9f 37 03 d5\s*dsb\s+nsh$")
	REGEX_ISB = re.compile(r"^\s*[0-9a-f]+:\s*df 3f 03 d5\s+isb$")

	state = STATE_DEFAULT
	for line in objdump_stdout:
		if state == STATE_DEFAULT:
			if re.match(REGEX_ERET, line):
				found_eret = True
				state = STATE_EXPECT_DSB_NSH
		elif state == STATE_EXPECT_DSB_NSH:
			if re.match(REGEX_DSB_NSH, line):
				state = STATE_EXPECT_ISB
			else:
				raise Exception("ERET not followed by DSB NSH")
		elif state == STATE_EXPECT_ISB:
			if re.match(REGEX_ISB, line):
				state = STATE_DEFAULT
			else:
				raise Exception("ERET not followed by ISB")

	# Ensure that at least one instance was found, otherwise the regexes are
	# probably wrong.
	if not found_eret:
		raise Exception("Could not find any ERET instructions")

def Main():
	parser = argparse.ArgumentParser()
	parser.add_argument("input_elf",
		help="ELF file to analyze")
	parser.add_argument("stamp_file",
		help="file to be touched if successful")
	args = parser.parse_args()

	objdump_stdout = subprocess.check_output([
		OBJDUMP, "-d", args.input_elf ])
	objdump_stdout = objdump_stdout.decode("utf-8").splitlines()

	check_eret_speculation_barrier(objdump_stdout)

	# Touch `stamp_file`.
	with open(args.stamp_file, "w"):
		pass

	return 0

if __name__ == "__main__":
	sys.exit(Main())
