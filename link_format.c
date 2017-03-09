/*
 * Media stream parser
 *
 * Authors: Simon Kuenzer <simon.kuenzer@neclab.eu>
 *
 *
 * Copyright (c) 2013-2017, NEC Europe Ltd., NEC Corporation All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * THIS HEADER MAY NOT BE EXTRACTED OR MODIFIED IN ANY WAY.
 */

#include "link_format.h"
#include "string.h"

enum lftype mime_to_lftype(const char *mime) {
	enum lftype ret;

	/* TODO: returned type is fixed type for now (independent of mime) */
	ret = LFT_RAW512;

	if (strcasecmp("audio/mpeg",     mime) == 0 ||
	    strcasecmp("audio/mpeg3",    mime) == 0 ||
	    strcasecmp("audio/x-mpeg-3", mime) == 0) {
		ret = LFT_MP3;
	}

	return ret;
}

int init_lformat(struct lfstate *lfs, enum lftype type, size_t offset)
{
	/* TODO: supported type is fixed for now */
	if (type == LFT_UNKNOWN)
		return -EINVAL;
  
	lfs->type = type;
	lfs->pos  = offset;
	lfs->joins.num = 0;
	lfs->joins.head = 0;
	return 0;
}

#define _lformat_add_join(lfs, off) \
	do { \
		if ((lfs)->joins.num)								\
			(lfs)->joins.head = ((lfs)->joins.head + 1)  % (LF_MAXNB_JOINS);	\
		else										\
			(lfs)->joins.head = 0;							\
		if ((lfs)->joins.num < (LF_MAXNB_JOINS))					\
			++(lfs)->joins.num;							\
		(lfs)->joins.offset[(lfs)->joins.head] = (off);				\
	} while(0)

int lformat_parse(struct lfstate *lfs, const char *b, size_t len)
{
	size_t next;

	lfs->pos += len;

	switch(lfs->type) {
	case LFT_RAW512:
		next = lformat_getrjoin(lfs) + 512;
		while (next < lfs->pos) {
			_lformat_add_join(lfs, next);
			next += 512;
		}
		break;

	case LFT_MP3:
		next = lformat_getrjoin(lfs) + 81920;
		while (next < lfs->pos) {
			_lformat_add_join(lfs, next);
			next += 81920;
		}
		break;

	default: /* unsupported type */
		break;
	}

	return 0;
}
