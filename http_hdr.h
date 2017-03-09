/*
 * Fast HTTP Server Implementation for SHFS volumes
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

#ifndef _HTTP_HDR_H_
#define _HTTP_HDR_H_

#include <target/sys.h>
#include <inttypes.h>
#include <lwip/opt.h>
#include "http_parser.h"
#include "http_data.h"

#define HTTP_RECVHDR_MAXNB_LINES   12
#define HTTP_SENDHDR_MAXNB_SLINES  8
#define HTTP_SENDHDR_MAXNB_DLINES  4
#define HTTP_HDR_DLINE_MAXLEN      80

#ifndef min
#define min(a, b) \
    ({ __typeof__ (a) __a = (a); \
       __typeof__ (b) __b = (b); \
       __a < __b ? __a : __b; })
#endif
#ifndef min3
#define min3(a, b, c) \
	min(min((a), (b)), (c))
#endif

struct _hdr_dbuffer {
	char b[HTTP_HDR_DLINE_MAXLEN];
	size_t len;
};

#define _hdr_dbuffer_reset(dbffr) \
	do { (dbffr)->len = 0; } while(0)
#define _hdr_dbuffer_terminate(dbffr) \
	do { \
		ASSERT((dbffr)->len < HTTP_HDR_DLINE_MAXLEN); \
		(dbffr)->b[(dbffr)->len++] = '\0'; \
	} while(0)
static inline void _hdr_dbuffer_add(struct _hdr_dbuffer *dbffr, const char *src, size_t len)
{
	register size_t curpos, maxlen;

	curpos = dbffr->len;
	maxlen = sizeof(dbffr->b) - 1 - curpos; /* minus 1 to store terminating '\0' later */

	len = maxlen < len ? maxlen : len;
	memcpy(&dbffr->b[curpos], src, len);
	dbffr->len += len;
}

struct _hdr_sbuffer {
	const char *b;
	size_t len;
};

struct _hdr_line {
	struct _hdr_dbuffer field;
	struct _hdr_dbuffer value;
};

struct http_recv_hdr {
	struct _hdr_line line[HTTP_RECVHDR_MAXNB_LINES];
	uint32_t nb_lines;

	int last_was_value;
	int overflow; /* more lines in received header than memory available */
};

struct http_send_hdr {
	struct _hdr_sbuffer sline[HTTP_SENDHDR_MAXNB_SLINES];
	struct _hdr_dbuffer dline[HTTP_SENDHDR_MAXNB_DLINES];
	uint32_t nb_slines;
	size_t slines_tlen;
	uint32_t nb_dlines;
	size_t dlines_tlen;
	size_t total_len;
};

#define http_sendhdr_add_sline(shdr, l, bffr, bffr_len) \
	do { \
		ASSERT(*(l) < HTTP_SENDHDR_MAXNB_SLINES);	\
		(shdr)->sline[*(l)].b = (bffr);		\
		(shdr)->sline[*(l)].len = (bffr_len);		\
		++*(l);					\
	} while(0)
#define http_sendhdr_add_shdr(shdr, l, idx) \
	do { \
		register unsigned i = (idx); \
		http_sendhdr_add_sline((shdr), (l), _http_shdr[i], _http_shdr_len[i]); \
	} while(0)
#define http_sendhdr_add_dline(shdr, l, fmt, ...)	  \
	do { \
		ASSERT(*(l) < HTTP_SENDHDR_MAXNB_DLINES);	\
		(shdr)->dline[*(l)].len =			\
			snprintf((shdr)->dline[*(l)].b,	\
			         HTTP_HDR_DLINE_MAXLEN,	\
			         (fmt),			\
			         ##__VA_ARGS__);		\
		++*(l);					\
	} while(0)
#define http_sendhdr_set_nbdlines(shdr, l) \
	do { (shdr)->nb_dlines = (l); } while(0)
#define http_sendhdr_get_nbdlines(shdr) \
	(shdr)->nb_dlines
#define http_sendhdr_set_nbslines(shdr, l) \
	do { (shdr)->nb_slines = (l); } while(0)
#define http_sendhdr_get_nbslines(shdr) \
	(shdr)->nb_slines
#define http_sendhdr_reset(shdr) \
	do { \
		http_sendhdr_set_nbdlines((shdr), 0);	\
		http_sendhdr_set_nbslines((shdr), 0);	\
	} while(0)
#define http_sendhdr_calc_totallen(shdr) \
	({ \
		register unsigned l;					\
		size_t ret;						\
									\
		(shdr)->slines_tlen = 0;				\
		for (l = 0; l < (shdr)->nb_slines; ++l)		\
		  (shdr)->slines_tlen += (shdr)->sline[l].len;		\
		(shdr)->dlines_tlen = 0;				\
		for (l = 0; l < (shdr)->nb_dlines; ++l)		\
		  (shdr)->dlines_tlen += (shdr)->dline[l].len;		\
		(shdr)->total_len = (shdr)->slines_tlen + (shdr)->dlines_tlen;	\
		ret = (shdr)->total_len + _http_sep_len;		\
		ret;							\
	})

typedef  err_t (*tcpwrite_fn_t)(void *, const void *, size_t *, uint8_t);
static inline err_t http_sendhdr_write(struct http_send_hdr *shdr, size_t *sent,
				       tcpwrite_fn_t tcpwrite, void *tcpwrite_argp)
{
	register unsigned l;
	size_t apos = *sent;     /* absolute offset in hdr */
	size_t aoff_cl, aoff_nl; /* current/next line buffer absolut offset in hdr */
	size_t l_off;            /* offset in current hdr line */
	size_t l_left;           /* left of current hdr line */
	void *ptr;
	size_t slen;
	err_t err = ERR_OK;

	if (apos < shdr->slines_tlen) {
		/* static header */
		aoff_nl = 0;
		for (l = 0; l < shdr->nb_slines; ++l) {
			aoff_cl  = aoff_nl;
			aoff_nl += shdr->sline[l].len;
			if ((aoff_cl <= apos) && (apos < aoff_nl)) {
				l_off  = apos - aoff_cl;
				l_left = shdr->sline[l].len - l_off;
				slen = l_left;
				ptr  = (uint8_t *) shdr->sline[l].b + l_off;

				err     = tcpwrite(tcpwrite_argp, ptr, &slen, TCP_WRITE_FLAG_MORE);
				apos   += slen;
				l_left -= slen;
				if ((err != ERR_OK) || (l_left))
					goto out;
			}
		}
	}
	if ((apos >= shdr->slines_tlen) &&
	    (apos <  shdr->total_len)) {
		/* dynamic header */
		aoff_nl = shdr->slines_tlen;
		for (l = 0; l < shdr->nb_dlines; ++l) {
			aoff_cl  = aoff_nl;
			aoff_nl += shdr->dline[l].len;
			if ((aoff_cl <= apos) && (apos < aoff_nl)) {
				l_off  = apos - aoff_cl;
				l_left = shdr->dline[l].len - l_off;
				slen = l_left;
				ptr  = (uint8_t *) shdr->dline[l].b + l_off;

				err     = tcpwrite(tcpwrite_argp, ptr, &slen, TCP_WRITE_FLAG_MORE);
				apos   += slen;
				l_left -= slen;
				if ((err != ERR_OK) || (l_left))
					goto out;
			}
		}
	}
	if (apos >= shdr->total_len) {
		/* end of header */
		l_off  = apos - shdr->total_len;
		l_left = _http_sep_len - l_off;
		slen = l_left;
		ptr  = (uint8_t *) _http_sep + l_off;

		err     = tcpwrite(tcpwrite_argp, ptr, &slen, TCP_WRITE_FLAG_MORE);
		apos   += slen;
	}

 out:
	*sent = apos;
	return err;
}

static inline int httpparser_recvhdr_field(struct http_parser *parser, const char *buf, size_t len)
{
	struct http_recv_hdr *rhdr = (struct http_recv_hdr *) parser->data;
	register unsigned l;

	if (unlikely(rhdr->overflow))
		return 0; /* ignore line */
	if (rhdr->last_was_value) {
		if (unlikely(rhdr->nb_lines == HTTP_RECVHDR_MAXNB_LINES)) {
			/* overflow */
			rhdr->overflow = 1;
			return 0;
		}

		/* switch to next line and reset its buffer */
		rhdr->last_was_value = 0;
		rhdr->line[rhdr->nb_lines].field.len = 0;
		rhdr->line[rhdr->nb_lines].value.len = 0;
		++rhdr->nb_lines;
	}

	l = rhdr->nb_lines - 1;
	_hdr_dbuffer_add(&rhdr->line[l].field, buf, len);
	return 0;
}

static inline int httpparser_recvhdr_value(struct http_parser *parser, const char *buf, size_t len)
{
	struct http_recv_hdr *rhdr = (struct http_recv_hdr *) parser->data;
	register unsigned l;

	if (unlikely(rhdr->overflow))
		return 0; /* ignore line */
	if (unlikely(!rhdr->last_was_value))
		rhdr->last_was_value = 1; /* value parsing began */
	if (unlikely(rhdr->nb_lines == 0))
		return -EINVAL; /* parsing error */

	l = rhdr->nb_lines - 1;
	_hdr_dbuffer_add(&rhdr->line[l].value, buf, len);
	return 0;
}

static inline void http_recvhdr_terminate(struct http_recv_hdr *rhdr)
{
	/* finalize request_hdr lines by adding terminating '\0' */
	register unsigned l;

	for (l = 0; l < rhdr->nb_lines; ++l) {
		_hdr_dbuffer_terminate(&rhdr->line[l].field);
		_hdr_dbuffer_terminate(&rhdr->line[l].value);
	}
}

/* returns the field line number on success, -1 if it was not found */
static inline int http_recvhdr_findfield(struct http_recv_hdr *rhdr, const char *field)
{
	register unsigned l;

	for (l = 0; l < rhdr->nb_lines; ++l) {
		if (strncasecmp(field, rhdr->line[l].field.b,
		                rhdr->line[l].field.len) == 0) {
			return (int) l;
		}
	}
	return -1; /* not found */
}

#define http_recvhdr_get_nblines(rhdr) \
	(rhdr)->nb_lines
#define http_recvhdr_reset(rhdr) \
	do { \
		(rhdr)->nb_lines = 0;		\
		(rhdr)->last_was_value = 1;	\
		(rhdr)->overflow = 0;		\
	} while(0)

#endif /* _HTTP_HDR_H_ */
