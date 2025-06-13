# Copyright 2025 The Hafnium Authors.
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/BSD-3-Clause.

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
