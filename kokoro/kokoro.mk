# Copyright 2025 The Hafnium Authors.
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/BSD-3-Clause.

# Resolve Hafnium root directory, from this Makefile's location.
HAFNIUM_DIR := $(realpath $(dir $(lastword $(MAKEFILE_LIST)))/..)
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
	@echo "[+] Cleaning Shrinkwrap build artifacts for hafnium-tftf.yaml"
	$(SHRINKWRAP) --runtime=null clean hafnium-tftf.yaml \
			--overlay=clean.yaml \
			--verbose

.PHONY: test_tftf_build
test_tftf_build:
	@echo "[+] Building from Hafnium root: $(HAFNIUM_SRC)"
	$(SHRINKWRAP) --runtime=null build \
		--btvar=HAFNIUM_SRC=$(HAFNIUM_DIR) \
		hafnium-tftf.yaml \
		--no-sync=hafnium \
		--verbose

.PHONY: test_tftf_run
test_tftf_run:
	@echo "[+] Running hafnium-tftf.yaml on FVP..."
	$(SHRINKWRAP) --runtime=null run hafnium-tftf.yaml

.PHONY: test_tftf
test_tftf: test_tftf_build test_tftf_run
