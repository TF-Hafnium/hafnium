/*
 * Copyright 2020 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

/**
 * Print one character to standard output.
 * This is intentionally called differently from functions in <stdio.h> so as to
 * avoid clashes when linking against libc.
 */
void stdout_putchar(char c);
void stdout_flush(void);
