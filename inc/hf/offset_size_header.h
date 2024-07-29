/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

/**
 * This header file is intended for use by files compiled with the
 * 'offset_size_header' build rule. See overview in 'offset_size_header.gni'.
 */

#pragma once

#if (defined GENERATE_BINARY) && (defined VERIFY_HEADER)
#error Only one action can be specified

#elif defined GENERATE_BINARY

/**
 * File being compiled to generate binaries with definitions of constants.
 */

/**
 * Emit a function with an embedded string in the format:
 *     <HAFNIUM_DEFINE name value />
 * These will be recognized by a script that generates the header file.
 */
#define DEFINE(sym, val)                                    \
	void gen_header__##sym(void)                        \
	{                                                   \
		__asm__ volatile(                           \
			"\n"                                \
			".ascii \"\\n<HAFNIUM_DEFINE " #sym \
			" %0 />\\n\"\n"                     \
			".align 8\n" /* Align epilogue */   \
			:                                   \
			: "i"(val));                        \
	}

#define DEFINE_SIZEOF(sym, type) DEFINE(sym, sizeof(type))
#define DEFINE_OFFSETOF(sym, type, field) DEFINE(sym, offsetof(type, field))

#elif defined VERIFY_HEADER

/**
 * File being compiled as part of the main build to check the values in
 * the auto-generated header file (included using a command-line flag).
 */

#include "hf/static_assert.h"

#define DEFINE_SIZEOF(sym, type)                                 \
	void gen_header__##sym(void)                             \
	{                                                        \
		static_assert(sizeof(type) == (sym),             \
			      "Generated struct size mismatch"); \
	}

#define DEFINE_OFFSETOF(sym, type, field)                          \
	void gen_header__##sym(void)                               \
	{                                                          \
		static_assert(offsetof(type, field) == (sym),      \
			      "Generated struct offset mismatch"); \
	}

#else
#error No action specified
#endif
