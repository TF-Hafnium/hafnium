/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

#include <stdbool.h>

/**
 * Returns true if the FFA_SECONDARY_EP_REGISTER interface is supported at
 * the virtual FF-A instance.
 */
bool plat_ffa_is_secondary_ep_register_supported(void);
