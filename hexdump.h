/* 
 * Copyright 2013 NEC Laboratories Europe
 *                Simon Kuenzer
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
#ifndef _HEXDUMP_H_
#define _HEXDUMP_H_

enum hd_addr_type {
  HDAT_NONE = 0,
  HDAT_RELATIVE,
  HDAT_ABSOLUTE
};

/**
 * hexdump - print a text hexdump for a binary blob of data
 * @buf: data blob to dump
 * @len: number of bytes in the @buf
 * @prefix_str: null-terminated string that is prefixed to each line
 * @addr_type: controls whether the offset address, full address, or none
 *  is printed in front of each line (%HDAT_OFFSET, %HDAT_FULL, %HDAT_NONE)
 * @rowlen: number of buffer bytes to print per line
 * @groupsize: number of bytes to print as group together
 * @show_ascii_comlumn: include ASCII after the hex output
 *
 * Example output using %HDAT_RELATIVE and 4-byte mode:
 * 0009ab42: 40 41 42 43  44 45 46 47 @ABCD EFGH
 * Example output using %HDAT_ABSOLUTE and 2-byte mode:
 * ffffffff88089af0: 73 72  71 70  77 76  75 74 pq rs tu vw
 */
void hexdump(const void *buf, size_t len,
             const char *prefix_str, enum hd_addr_type addr_type,
             size_t rowsize, size_t groupsize,
             int show_ascii_column);

/**
 * printh - shorthand form of print_hex_dump() with default params
 * @buf: data blob to dump
 * @len: number of bytes in the @buf
 *
 * Calls hexdump(), with rowsize of 16, groupsize of 4,
 * and enabled ASCII column output.
 */
#define printh(buf, len) \
    hexdump((buf), (len), "", HDAT_RELATIVE, 16, 4, 1)

#endif /* _HEXDUMP_H_ */
