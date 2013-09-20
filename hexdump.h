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
#ifndef _HEXDUMP_H_
#define _HEXDUMP_H_

enum hd_addr_type {
  HDAT_NONE = 0,
  HDAT_OFFSET,
  HDAT_FULL
};

int hex2bin(uint8_t *dst, const char *src, size_t count);
void hexdump2buffer(const void *buf, size_t len, int rowsize,
					int groupsize, int show_ascii_column,
					char *trglinebuf, size_t trglinebuflen);
void print_hexdump(const void *buf, size_t len, const char *prefix_str,
				   enum hd_addr_type addr_type, int rowsize,
				   int groupsize, int show_ascii_column);

/**
 * printh - shorthand form of print_hex_dump() with default params
 * @buf: data blob to dump
 * @len: number of bytes in the @buf
 *
 * Calls print_hex_dump(), with rowsize of 16, groupsize of 1,
 * and ASCII column output.
 */
#define printh(buf, len) \
  print_hexdump((buf), (len), "", HDAT_OFFSET, 16, 1, 1);

#endif /* _HEXDUMP_H_ */
