/* 
 * Copyright 2012 Simon Sturm
 *
 * hexdump is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 2.0 of the License, or (at your
 * option) any later version.
 *
 * hexdump is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with bytewiseRead. If not, see
 * <http://www.gnu.org/licenses/>.
 */
/*
 * This is a MiniOS port of hexdump
 */

#include <mini-os/os.h>
#include <mini-os/types.h>
#include <mini-os/xmalloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#include "hexdump.h"

static const char hex_asc[] = "0123456789abcdef";
#ifndef hex_asc_lo
  #define hex_asc_lo(i) hex_asc[(i) & 0x0f]
#endif
#ifndef hex_asc_hi
  #define hex_asc_hi(i) hex_asc[((i) & 0x0f0) >> 4]
#endif
#ifndef min
  #define min(x, y) (((x) < (y)) ? (x) : (y))
#endif

/**
 * hexchar2bin - convert a hex digit to its real value
 * @ch: ascii character represents hex digit
 *
 * hexchar2bin() returns the converted one hex digit to its actual
 * value or -1 in case of bad input.
 */
static inline int hexchar2bin(char ch)
{
	if ((ch >= '0') && (ch <= '9'))
		return ch - '0';
	ch = tolower(ch);
	if ((ch >= 'a') && (ch <= 'f'))
		return ch - 'a' + 10;
	return -1;
}

/**
 * hex2bin - convert an ascii hexadecimal string to its binary representation
 * @dst: binary result
 * @src: ascii hexadecimal string
 * @count: result length
 *
 * Returns 0 on success, -1 in case of bad input.
 */
int hex2bin(uint8_t *dst, const char *src, size_t count)
{
	while (count--) {
		int hi = hexchar2bin(*src++);
		int lo = hexchar2bin(*src++);

		if ((hi < 0) || (lo < 0))
			return -1;

		*dst++ = (hi << 4) | lo;
	}
	return 0;
}

/**
 * hexdump2buffer - convert a blob of data to a "ASCII hex" line (string)
 * @buf: data blob to dump
 * @len: number of bytes in the @buf
 * @rowsize: number of buffer bytes to print per line; must be 16 or 32
 * @groupsize: number of bytes to print as group together (1, 2, 4, 8)
 * @linebuf: where to put the hexdump string
 * @linebuflen: total size of @linebuf, including terminating \0 character
 * @show_ascii_comlumn: include ASCII after the hex output
 *
 * hex_dump_to_buffer() works on one "line" of output at a time, i.e.,
 * 16 or 32 bytes of input data converted to hex + ASCII output.
 *
 * Given a buffer of uint8_t data, hexdump2buffer() converts the input data
 * to a hex + ASCII dump at the supplied memory location.
 * The converted output (string) is always NUL-terminated (\0).
 *
 * E.g.:
 *   hex_dump_to_buffer(frame->data, frame->len, 16, 1, 1,
 *			linebuf, sizeof(linebuf));
 *
 * example output buffer:
 * 40 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f  @ABCDEFGHIJKLMNO
 */
void hexdump2buffer(const void *buf, size_t len, int rowsize,
					int groupsize, int show_ascii_column,
					char *trglinebuf, size_t trglinebuflen)
{
	const uint8_t *ptr = buf;
	uint8_t ch;
	int j, lx = 0;
	int ascii_column;

	ASSERT(rowsize == 16 || rowsize == 32);
	ASSERT(groupsize == 1 || groupsize == 2 || groupsize == 4 || groupsize == 8);

	if (!len)
		goto nil;
	if (len > rowsize)		/* limit to one line at a time */
		len = rowsize;
	if ((len % groupsize) != 0)	/* no mixed size output */
		groupsize = 1;

	switch (groupsize) {
	case 8: {
		const uint64_t *ptr8 = buf;
		int ngroups = len / groupsize;

		for (j = 0; j < ngroups; j++)
			lx += snprintf(trglinebuf + lx, trglinebuflen - lx,
					"%s%16.16llx", j ? " " : "",
					(unsigned long long)*(ptr8 + j));
		ascii_column = 17 * ngroups + 2;
		break;
	}

	case 4: {
		const uint32_t *ptr4 = buf;
		int ngroups = len / groupsize;

		for (j = 0; j < ngroups; j++)
			lx += snprintf(trglinebuf + lx, trglinebuflen - lx,
					"%s%8.8x", j ? " " : "", *(ptr4 + j));
		ascii_column = 9 * ngroups + 2;
		break;
	}

	case 2: {
		const uint16_t *ptr2 = buf;
		int ngroups = len / groupsize;

		for (j = 0; j < ngroups; j++)
			lx += snprintf(trglinebuf + lx, trglinebuflen - lx,
					"%s%4.4x", j ? " " : "", *(ptr2 + j));
		ascii_column = 5 * ngroups + 2;
		break;
	}

	default: /* 1 */
		for (j = 0; (j < len) && (lx + 3) <= trglinebuflen; j++) {
			ch = ptr[j];
			trglinebuf[lx++] = hex_asc_hi(ch);
			trglinebuf[lx++] = hex_asc_lo(ch);
			trglinebuf[lx++] = ' ';
		}
		if (j)
			lx--;

		ascii_column = 3 * rowsize + 2;
		break;
	}
	if (!show_ascii_column)
		goto nil;

	while (lx < (trglinebuflen - 1) && lx < (ascii_column - 1))
		trglinebuf[lx++] = ' ';
	for (j = 0; (j < len) && (lx + 2) < trglinebuflen; j++) {
		ch = ptr[j];
		trglinebuf[lx++] = (isascii(ch) && isprint(ch)) ? ch : '.';
	}
nil:
	trglinebuf[lx++] = '\0';
}

/**
 * print_hexdump - print a text hexdump for a binary blob of data
 * @buf: data blob to dump
 * @len: number of bytes in the @buf
 * @prefix_str: string to prefix each line with;
 *  caller supplies trailing spaces for alignment if desired
 * @addr_type: controls whether the offset address, full address, or none
 *  is printed in front of each line (%HDAT_OFFSET, %HDAT_FULL, %HDAT_NONE)
 * @rowsize: number of buffer bytes to print per line; must be 16 or 32
 * @groupsize: number of bytes to print as group together (1, 2, 4, 8)
 * @show_ascii_comlumn: include ASCII after the hex output
 *
 * Given a buffer of u8 data, print_hexdump() prints a hex + ASCII dump
 * to stdout.
 *
 * E.g.:
 *   print_hex_dump(KERN_DEBUG, "raw data: ", DUMP_PREFIX_ADDRESS,
 *		    16, 1, frame->data, frame->len, true);
 *
 * Example output using %HDAT_OFFSET and 1-byte mode:
 * 0009ab42: 40 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f  @ABCDEFGHIJKLMNO
 * Example output using %HDAT_FULL and 4-byte mode:
 * ffffffff88089af0: 73727170 77767574 7b7a7978 7f7e7d7c  pqrstuvwxyz{|}~.
 */
void print_hexdump(const void *buf, size_t len, const char *prefix_str,
				   enum hd_addr_type addr_type, int rowsize, int groupsize,
				   int show_ascii_column)
{
	const uint8_t *ptr = buf;
	int i, linelen, remaining = len;
	char linebuf[32 * 3 + 2 + 32 + 1];

	if (rowsize != 16 && rowsize != 32)
		rowsize = 16;

	for (i = 0; i < len; i += rowsize) {
		linelen = min(remaining, rowsize);
		remaining -= rowsize;

		hexdump2buffer(ptr + i, linelen, rowsize, groupsize,
					   show_ascii_column, linebuf, sizeof(linebuf));

		switch (addr_type) {
		case HDAT_FULL:
			printf("%s%p: %s\n",
			       prefix_str, ptr + i, linebuf);
			break;
		case HDAT_OFFSET:
			printf("%s%.8x: %s\n", prefix_str, i, linebuf);
			break;
		default: /* HDAT_NONE */
			printf("%s%s\n", prefix_str, linebuf);
			break;
		}
	}
}
