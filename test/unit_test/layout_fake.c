/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/layout.h"

paddr_t layout_text_begin(void)
{
	return pa_init(1);
}

paddr_t layout_text_end(void)
{
	return pa_init(100);
}

paddr_t layout_rodata_begin(void)
{
	return pa_init(200);
}

paddr_t layout_rodata_end(void)
{
	return pa_init(300);
}

paddr_t layout_data_begin(void)
{
	return pa_init(400);
}

paddr_t layout_data_end(void)
{
	return pa_init(500);
}

paddr_t layout_image_end(void)
{
	return pa_init(600);
}

paddr_t layout_stacks_begin(void)
{
	return pa_init(700);
}

paddr_t layout_stacks_end(void)
{
	return pa_init(700);
}

paddr_t layout_primary_begin(void)
{
	return pa_init(0x80000);
}
