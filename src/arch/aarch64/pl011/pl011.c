/*
 * Copyright 2018 The Hafnium Authors.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/BSD-3-Clause.
 */

#include "hf/io.h"
#include "hf/mm.h"
#include "hf/mpool.h"
#include "hf/plat/console.h"

/* UART Data Register. */
#define UART_DR IO32_C(PL011_BASE + 0x0)

/* Receive Status or Error Clear Register. */
#define UART_RSR_ECR IO32_C(PL011_BASE + 0x4)

/* UART Flag Register. */
#define UART_FR IO32_C(PL011_BASE + 0x018)

/* UART IBRD (Integer Baudrate) Register. */
#define UART_IBRD IO32_C(PL011_BASE + 0x024)

/* UART FBRD (Fractional Baudrate) Register. */
#define UART_FBRD IO32_C(PL011_BASE + 0x028)

/* UART Line Control Register. */
#define UART_LCR_H IO32_C(PL011_BASE + 0x02C)

/* UART Control Register. */
#define UART_CR IO32_C(PL011_BASE + 0x030)

/* UART Interrupt Mask Set/Clear Register. */
#define UART_IMSC IO32_C(PL011_BASE + 0x038)

/* UART Flag Register bit: transmit fifo is full. */
#define UART_FR_TXFF (1 << 5)

/* UART Flag Register bit: receive fifo is empty */
#define UART_FR_RXFE (1 << 4)

/* UART Flag Register bit: UART is busy. */
#define UART_FR_BUSY (1 << 3)

/* UART transmit/receive line register bits. */
#define UART_LCRH_WLEN_8 (3 << 5)

/* UART control register bits. */
#define UART_CR_RXE (1 << 9)
#define UART_CR_TXE (1 << 8)
#define UART_CR_UARTEN (1 << 0)

#define UART_IMSC_RTIM (1 << 6)
#define UART_IMSC_RXIM (1 << 4)

void plat_console_init(void)
{
	/*
	 * If pl011 clock frequency is 0 or not specified, then don't set
	 * baudrate as it can't be calculated without clock frequency.
	 * Assumption is that the default rate is fine for the system.
	 */
#if PL011_CLOCK != 0

	unsigned int quotient = PL011_CLOCK * 4 / PL011_BAUDRATE;

	/* Disable everything */
	io_write32(UART_CR, 0);
	/* Clear all errors */
	io_write32(UART_RSR_ECR, 0);

	/* Set baud rate */
	io_write32(UART_FBRD, quotient & 0x3f);
	io_write32(UART_IBRD, quotient >> 6);

	/* Configure TX to 8 bits, 1 stop bit, no parity, fifo disabled. */
	io_write32(UART_LCR_H, UART_LCRH_WLEN_8);

	/* Enable interrupts for receive and receive timeout */
	io_write32(UART_IMSC, UART_IMSC_RXIM | UART_IMSC_RTIM);

	/* Enable UART and RX/TX */
	io_write32(UART_CR, UART_CR_UARTEN | UART_CR_TXE | UART_CR_RXE);
#endif
}

void plat_console_mm_init(struct mm_stage1_locked stage1_locked,
			  struct mpool *ppool)
{
	/* Map page for UART. */
	mm_identity_map(stage1_locked, pa_init(PL011_BASE),
			pa_add(pa_init(PL011_BASE), PAGE_SIZE),
			MM_MODE_R | MM_MODE_W | MM_MODE_D, ppool);
}

/*
 * Since the recursion is only one level disable the clang tidy recursion check
 */
// NOLINTNEXTLINE(misc-no-recursion)
void plat_console_putchar(char c)
{
	/* Print a carriage-return as well. */
	if (c == '\n') {
		plat_console_putchar('\r');
	}

	/* Wait until there is room in the tx buffer. */
	while (io_read32(UART_FR) & UART_FR_TXFF) {
		/* do nothing */
	}

	/* Write the character out, force memory access ordering. */
	memory_ordering_barrier();
	io_write32(UART_DR, c);
	memory_ordering_barrier();

	/* Wait until the UART is no longer busy. */
	while (io_read32_mb(UART_FR) & UART_FR_BUSY) {
		/* do nothing */
	}
}

char plat_console_getchar(void)
{
	/* Wait until the UART is no longer busy and has data to read. */
	while (io_read32_mb(UART_FR) & UART_FR_BUSY ||
	       io_read32_mb(UART_FR) & UART_FR_RXFE) {
		/* do nothing */
	}

	return (char)(io_read32(UART_DR) & 0xFF);
}
