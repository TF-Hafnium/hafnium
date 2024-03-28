/*
 * Copyright 2024 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

.global memcpy_trapped
.global memcpy_trapped_aborted
.global memcpy_trapped_write
.global memcpy_trapped_read

/**
 * This is a helper function to copy data from/to memory owned
 * by partitions or another FF-A endpoint, whose access from the
 * SPM might result in a data abort, due to accessing the wrong
 * Physical Address. This function shall not be used to copy when
 * source and destination are owned by hafnium.
 * The function assumes the addresses are aligned to 8 bytes.
 *
 * - x0 contains the destination address.
 * - x1 size of destination
 * - x2 contains the source address.
 * - x3 size of source.
 *
 * Returns:
 * - x0: 0 if failed to copy, 1 otherwise.
 */
memcpy_trapped:
	/* If source size is bigger than destination size, abort. */
	cmp x3, x1
	b.hi memcpy_trapped_aborted

	/* Return error if destination size is 0. */
	cbz x1, memcpy_trapped_aborted

	/* Return error if destination is null. */
	cbz x0, memcpy_trapped_aborted

	/* Return error if source is null. */
	cbz x2, memcpy_trapped_aborted

	/* Check if source size is aligned to 8 bytes. */
	and x4, x3, #(8-1)
	cbz x4, memcpy_trapped_read

	/* Align to 8 bytes if it isn't. */
	add x3, x3, #8
	sub x3, x3, x4

	/*
	 * The read/write from/to memory prone to cause an
	 * exception must precisely follow the labels below.
	 * This is so we can deterministically assert that the
	 * exception is due to an access that we know to be
	 * prone to be aborted.
	 * This is enforced in the exception handler, to
	 * determine wether the link register must be overwritten
	 * with that of label `memcpy_trapped_aborted`, thus
	 * returning an error to the caller of memcpy_trapped.
	 */
memcpy_trapped_read:
	/* Read from the source. */
	ldr x4, [x2], #8
memcpy_trapped_write:
	/* Write to destination. */
	str x4, [x0], #8
	sub x3, x3, #8
	cbnz x3, memcpy_trapped_read

	/* Success. */
	mov x0, #1
	ret

/**
 * Exit for 'memcpy_trapped' function, in case there is an error:
 * - Argument checks in the function.
 * - Access gets trapped due to GPF.
 */
memcpy_trapped_aborted:
	mov x0, xzr
	ret
