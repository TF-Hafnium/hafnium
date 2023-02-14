/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/stdout.h"

#include "vmapi/hf/call.h"

void stdout_putchar(char c)
{
	ffa_console_log_32((const char *)&c, 1);
}
