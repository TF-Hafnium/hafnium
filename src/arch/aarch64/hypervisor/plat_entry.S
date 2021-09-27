/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

.section .init.image_entry, "ax"
.weak plat_entry
plat_entry:
	/* Do nothing. */
	ret
