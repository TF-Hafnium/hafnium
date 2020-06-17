/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/arch/vm/events.h"

void event_wait(void)
{
	__asm__ volatile("wfe");
}

void event_send_local(void)
{
	__asm__ volatile("sevl");
}
