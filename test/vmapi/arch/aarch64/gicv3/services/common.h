/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "vmapi/hf/ffa.h"

void mailbox_receive_retry(void *buffer, size_t buffer_size, void *recv,
			   struct ffa_partition_rxtx_header *header);
