/*
 * Copyright 2019 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#pragma once

/**
 * Header for Hafnium messages
 *
 * NOTE: This is a work in progress.  The final form of a Hafnium message header
 * is likely to change.
 */
struct hf_msg_hdr {
	uint64_t src_port;
	uint64_t dst_port;
};
