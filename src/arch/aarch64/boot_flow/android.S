/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

.section .init.plat_boot_flow_hook, "ax"
.global plat_boot_flow_hook
plat_boot_flow_hook:
	/* Do nothing. */
	ret
