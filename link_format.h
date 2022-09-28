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
 */

#ifndef _LINK_FORMAT_H_
#define _LINK_FORMAT_H_

#include <stddef.h>
#include <inttypes.h>
#include <errno.h>

#define LF_MAXNB_JOINS 2 /* keep two recent join offsets */

enum lftype {
	LFT_UNKNOWN = 0,
	LFT_RAW512, /* 512B */
	LFT_MP3, /* 80KB */
};

struct lfstate {
	enum lftype type;

	/* state of parser */
	size_t offset;
	size_t pos;

	/* list of n recent join points */
	struct {
		size_t offset[LF_MAXNB_JOINS];
		unsigned int head;
		unsigned int num;
	} joins;
};

enum lftype mime_to_lftype(const char *mime);
int init_lformat(struct lfstate *lfs, enum lftype type, size_t offset);
int lformat_parse(struct lfstate *lfs, const char *b, size_t len);

static inline size_t lformat_getjoin(struct lfstate *lfs, unsigned idx)
{
	unsigned int p;

	/* index is outside of parser window?
	 * -> return initial offset */
	if (idx > lfs->joins.num)
		return lfs->offset;

	p = (idx > lfs->joins.head) ?
	  (LF_MAXNB_JOINS - (idx - lfs->joins.head)) :
	  lfs->joins.head - idx;
	return lfs->joins.offset[p];
}
/* most recent join */
#define lformat_getrjoin(lfs) \
  lformat_getjoin((lfs), 0)
/* oldest join in parser window */
#define lformat_getojoin(lfs) \
  lformat_getjoin((lfs), ((lfs)->num ? ((lfs)->num - 1) : 0))

#endif /* _LINK_FORMAT_H_ */
