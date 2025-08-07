# Copyright 2025 The Hafnium Authors.
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/BSD-3-Clause.

# Resolve Hafnium, TF-A and TF-A-Test directories, from this Makefile's location
HAFNIUM_DIR := $(realpath $(dir $(lastword $(MAKEFILE_LIST)))/..)
TFA_DIR     := $(realpath $(dir $(lastword $(MAKEFILE_LIST)))/../../trusted-firmware-a)
TFTF_DIR    := $(realpath $(dir $(lastword $(MAKEFILE_LIST)))/../../tf-a-tests)

HAFNIUM_TFTF_CONFIG := hafnium-tftf.yaml
SHRINKWRAP := shrinkwrap

# Named `test_` rather than `test` because make will not run the target if the
# `test` directory has not changed.
.PHONY: test_
test_: all
	./kokoro/test.sh

.PHONY: test_spmc
test_spmc: all
	./kokoro/test_spmc.sh

.PHONY: test_el3_spmc
test_el3_spmc: all
	./kokoro/test_el3_spmc.sh

.PHONY: test_tftf_clean
test_tftf_clean:
	@echo "[+] Cleaning Shrinkwrap build artifacts for $(HAFNIUM_TFTF_CONFIG)"
	$(SHRINKWRAP) --runtime=null clean $(HAFNIUM_TFTF_CONFIG) \
		--overlay=clean.yaml --verbose

.PHONY: test_tftf_build
test_tftf_build:
# Check for locally checked-out repos of Hafnium, TF-A, and TFTF.
# If present, build using local sources and disable Shrinkwrap syncing.
ifeq ($(strip $(shell \
	test -d "$(HAFNIUM_DIR)/.git" && \
	test -d "$(TFA_DIR)/.git" && \
	test -d "$(TFTF_DIR)/.git" && echo OK)),OK)
	@echo "[+] Using local sources from $(HAFNIUM_DIR), $(TFA_DIR), $(TFTF_DIR)"
	$(SHRINKWRAP) --runtime=null build $(HAFNIUM_TFTF_CONFIG) \
		--overlay=local-src.yaml \
		--btvar=HAFNIUM_SRC=$(HAFNIUM_DIR) \
		--btvar=TFA_SRC=$(TFA_DIR) \
		--btvar=TFTF_SRC=$(TFTF_DIR) \
		--no-sync-all \
		--verbose
else
	@echo "[!] One or more local repos not found — falling back to remote clone"
	@echo "[+] Building from Hafnium root: $(HAFNIUM_DIR)"
	$(SHRINKWRAP) --runtime=null build \
			--btvar=HAFNIUM_SRC=$(HAFNIUM_DIR) \
			$(HAFNIUM_TFTF_CONFIG) \
			--no-sync=hafnium \
			--verbose
endif

.PHONY: test_tftf_run
test_tftf_run:
	@echo "[+] Running $(HAFNIUM_TFTF_CONFIG) on FVP..."
	$(SHRINKWRAP) --runtime=null run $(HAFNIUM_TFTF_CONFIG)

.PHONY: test_tftf
test_tftf: test_tftf_build test_tftf_run
