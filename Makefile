# Copyright 2018 The Hafnium Authors.
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/BSD-3-Clause.

# Select the project to build.
PROJECT ?= reference

TOOLCHAIN_LIB := $(shell clang --print-resource-dir)

ENABLE_ASSERTIONS ?= 1

PLATFORM ?= default

LIST_SEPARATOR := ,
PLATFORM_LIST := $(subst $(LIST_SEPARATOR), ,$(PLATFORM))

GN_ARGS := project="$(PROJECT)"
GN_ARGS += toolchain_lib="$(TOOLCHAIN_LIB)"
ifeq ($(filter $(ENABLE_ASSERTIONS), 1 0),)
         $(error invalid value for ENABLE_ASSERTIONS, should be 1 or 0)
endif
GN_ARGS += enable_assertions="$(ENABLE_ASSERTIONS)"

# If HAFNIUM_HERMETIC_BUILD is "true" (not default), invoke `make` inside
# a container. The 'run_in_container.sh' script will set the variable value to
# 'inside' to avoid recursion.
ifeq ($(HAFNIUM_HERMETIC_BUILD),true)

# TODO: This is not ideal as (a) we invoke the container once per command-line
# target, and (b) we cannot pass `make` arguments to the script. We could
# consider creating a bash alias for `make` to invoke the script directly.

# Need to define at least one non-default target.
all:
	@$(CURDIR)/build/run_in_container.sh make PROJECT=$(PROJECT) \
		ENABLE_ASSERTIONS=$(ENABLE_ASSERTIONS) $@

# Catch-all target.
.DEFAULT:
	@$(CURDIR)/build/run_in_container.sh make PROJECT=$(PROJECT) \
		ENABLE_ASSERTIONS=$(ENABLE_ASSERTIONS) $@

else  # HAFNIUM_HERMETIC_BUILD

# Set path to prebuilts used in the build.
UNAME_S := $(shell uname -s | tr '[:upper:]' '[:lower:]')
UNAME_M := $(shell uname -m)

ifeq ($(UNAME_M),x86_64)
UNAME_M := x64
endif

PREBUILTS := $(CURDIR)/prebuilts/$(UNAME_S)-$(UNAME_M)
GN ?= $(PREBUILTS)/gn/gn
NINJA ?= $(PREBUILTS)/ninja/ninja

CHECKPATCH_SCRIPT:=$(CURDIR)/out/checkpatch/checkpatch.pl

CHECKPATCH := $(CHECKPATCH_SCRIPT) \
	--ignore BRACES,SPDX_LICENSE_TAG,VOLATILE,SPLIT_STRING,AVOID_EXTERNS,USE_SPINLOCK_T,NEW_TYPEDEFS,INITIALISED_STATIC,FILE_PATH_CHANGES,EMBEDDED_FUNCTION_NAME,SINGLE_STATEMENT_DO_WHILE_MACRO,MACRO_WITH_FLOW_CONTROL,PREFER_PACKED,PREFER_ALIGNED,INDENTED_LABEL,SPACING,PREFER_PRINTF --quiet

# Specifies the grep pattern for ignoring specific files in checkpatch.
# C++ headers, *.hh, are automatically excluded.
# Separate the different items in the list with a grep or (\|).
# debug_el1.c : uses XMACROS, which checkpatch doesn't understand.
# perfmon.c : uses XMACROS, which checkpatch doesn't understand.
# feature_id.c : uses XMACROS, which checkpatch doesn't understand.
# el1_physical_timer.c : uses XMACROS, which checkpatch doesn't understand.
CHECKPATCH_IGNORE := "src/arch/aarch64/hypervisor/debug_el1.c\|src/arch/aarch64/hypervisor/perfmon.c\|src/arch/aarch64/hypervisor/feature_id.c\|src/arch/aarch64/stack_protector.c\|src/arch/aarch64/inc/hf/arch/sve.h\|inc/hf/dlog.h\|inc/hf/arch/std.h\|inc/hf/panic.h\|inc/system/sys/cdefs.h\|inc/hf/bits.h\|src/arch/aarch64/hypervisor/el1_physical_timer.c"

# el1_physical_timer.c : Use of macros causes a fail due to identical consecutive branches in switch.
TIDY_IGNORE := "src/arch/aarch64/hypervisor/el1_physical_timer.c"

OUT ?= out/$(PROJECT)
OUT_DIR = $(OUT)

.PHONY: all
all: $(OUT_DIR)/build.ninja
ifeq ($(PLATFORM),default)
	@$(NINJA) -C $(OUT_DIR)
else
	@build/check_platform_exists.py $(PROJECT) $(PLATFORM_LIST) || (exit 1)
	@for PLAT in $(PLATFORM_LIST); do \
		$(NINJA) -C $(OUT_DIR) project/$(PROJECT):$$PLAT; \
	done
endif

$(OUT_DIR)/build.ninja:
	@$(GN) --export-compile-commands gen --args='$(GN_ARGS)' $(OUT_DIR)

doc:
	@echo "  BUILD DOCUMENTATION"
	make --no-print-directory -C docs html

.PHONY: clean
clean:
	@$(NINJA) -C $(OUT_DIR) -t clean

.PHONY: clobber
clobber:
	rm -rf $(OUT_DIR)

# see .clang-format.
.PHONY: format
format:
	@echo "Formatting..."
	@find src/ -name \*.c -o -name \*.cc -o -name \*.h | xargs -r clang-format -style file -i
	@find inc/ -name \*.c -o -name \*.cc -o -name \*.h | xargs -r clang-format -style file -i
	@find test/ -name \*.c -o -name \*.cc -o -name \*.h | xargs -r clang-format -style file -i
	@find project/ -name \*.c -o -name \*.cc -o -name \*.h | xargs -r clang-format -style file -i
	@find vmlib/ -name \*.c -o -name \*.cc -o -name \*.h | xargs -r clang-format -style file -i
	@find . \( -name \*.gn -o -name \*.gni \) | xargs -n1 $(GN) format

.PHONY: checkpatch
checkpatch: $(CHECKPATCH_SCRIPT)
	@find src/ -name \*.c -o -name \*.h | grep -v $(CHECKPATCH_IGNORE) | xargs $(CHECKPATCH) -f --no-tree
	@find inc/ -name \*.c -o -name \*.h | grep -v $(CHECKPATCH_IGNORE) | xargs $(CHECKPATCH) -f --no-tree
	# TODO: enable for test/
	@find project/ -name \*.c -o -name \*.h | grep -v $(CHECKPATCH_IGNORE) | xargs $(CHECKPATCH) -f --no-tree

$(CHECKPATCH_SCRIPT):
	@build/setup_checkpatch.sh

# see .clang-tidy.
.PHONY: tidy
tidy: $(OUT_DIR)/build.ninja
	@$(NINJA) -C $(OUT_DIR)
	@echo "Tidying..."
	# TODO: enable readability-magic-numbers once there are fewer violations.
	# TODO: enable for c++ tests as it currently gives spurious errors.
	@find src/ test/ -name '*.c' | grep -v $(TIDY_IGNORE) | xargs run-clang-tidy -quiet -p $(OUT_DIR) -fix

.PHONY: license
license:
	@find build/ -name \*.S -o -name \*.c -o -name \*.cc -o -name \*.h -o -name \*.dts -o -name \*.ld | xargs -n1 python3 build/license.py --style c
	@find inc/ -name \*.S -o -name \*.c -o -name \*.cc -o -name \*.h -o -name \*.dts | xargs -n1 python3 build/license.py --style c
	@find src/ -name \*.S -o -name \*.c -o -name \*.cc -o -name \*.h -o -name \*.dts | xargs -n1 python3 build/license.py --style c
	@find test/ -name \*.S -o -name \*.c -o -name \*.cc -o -name \*.h -o -name \*.dts | xargs -n1 python3 build/license.py --style c
	@find vmlib/ -name \*.S -o -name \*.c -o -name \*.cc -o -name \*.h -o -name \*.dts | xargs -n1 python3 build/license.py --style c
	@find build/ -name \*.py -o -name \*.sh -o -name \*.inc -o -name Dockerfile* | xargs -n1 python3 build/license.py --style hash
	@find kokoro/ -name \*.sh -o -name \*.cfg | xargs -n1 python3 build/license.py --style hash
	@find test/ -name \*.py| xargs -n1 python3 build/license.py --style hash

.PHONY: list
list:
	@build/check_platform_exists.py $(PROJECT)

endif  # HAFNIUM_HERMETIC_BUILD
