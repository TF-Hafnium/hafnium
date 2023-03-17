/*
 * Copyright 2020 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/stdout.h"

#include "hf/plat/console.h"

void stdout_putchar(char c)
{
	plat_console_putchar(c);
}

void stdout_flush(void)
{
}
