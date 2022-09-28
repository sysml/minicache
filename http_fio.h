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
 */

#ifndef _HTTP_FIO_H_
#define _HTTP_FIO_H_

#include "http_defs.h"
#include "http_hdr.h"

#define httpreq_fio_nb_buffers(chunksize)  (max(2,(DIV_ROUND_UP(HTTPREQ_SNDBUF, (size_t) chunksize))))

void httpreq_fio_aiocb(SHFS_AIO_TOKEN *t, void *cookie, void *argp);

/* async SHFS I/O */
#define httpreq_fio_nextidx(fstate, idx) \
        ((idx + 1) % (hreq)->f.cce_max_nb)

static inline int httpreq_fio_aioreq(struct http_req *hreq, chk_t addr, unsigned int cce_idx)
{
	/* called whenever an async I/O is completed */
	int ret;

	BUG_ON(hreq->f.cce_t);

	ret = shfs_cache_aread(addr,
	                       httpreq_fio_aiocb,
	                       hreq,
	                       NULL,
	                       &(hreq->f.cce[cce_idx]),
			       &(hreq->f.cce_t));
	if (ret < 0)
		printd("failed to perform request for chunk %"PRIchk" [cce_idx=%u]: %d\n", addr, cce_idx, ret);
	else
		printd("requested for chunk %"PRIchk" [cce_idx=%u]: %d (cce: %p, t: %p)\n", addr, cce_idx, ret, hreq->f.cce[cce_idx], hreq->f.cce_t);
	return ret;
}

static inline err_t httpreq_write_fio(struct http_req *hreq, size_t *sent)
{
	register size_t roff, foff;
	register size_t left;
	register chk_t  cur_chk;
	register size_t chk_off;
	register unsigned int idx;
	size_t slen;
	err_t err;
	int ret;

	idx = hreq->f.cce_idx;
	roff = *sent; /* offset in request */
	if (unlikely(roff == hreq->rlen))
		return ERR_OK; /* request is done already but we got called */
	foff = roff + hreq->f.rfirst;  /* offset in file */
	cur_chk = shfs_volchk_foff(hreq->fd, foff);

	/* unlink session from ioretry chain if it was linked before */
	/* TODO: Still needed? !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! */
	httpsess_unregister_ioretry(hreq->hsess);
 next:
	err = ERR_OK;

	/* is the chunk already requested? */
	if (unlikely(!hreq->f.cce[idx])) {
		ret = httpreq_fio_aioreq(hreq, cur_chk, idx);
		if (unlikely(ret == -EAGAIN)) {
			/* Retry I/O later because we are out of memory currently */
			printd("[idx=%u] could not perform I/O: append session to I/O retry chain...\n", idx, ret);
			httpsess_register_ioretry(hreq->hsess);
			httpsess_flush(hreq->hsess); /* enforce sending of enqueued data:
			                                we have no new data for now */
			err = ERR_OK;
			goto out;
		} else if (unlikely(ret < 0)) {
			/* I/O ERROR happened -> abort */
			printd("[idx=%u] fatal read error (%d): aborting...\n", idx, ret);
			httpsess_flush(hreq->hsess); /* enforce sending of enqueued data */
			err = ERR_ABRT;
			goto out;
		} else if (ret == 1) {
			/* current request is not done yet (hit+wait),
			 * we need to wait. httpsess_response
			 * will be recalled from within callback */
			printd("[idx=%u] chunk %"PRIchk" is not ready yet but request was sent\n", idx, cur_chk);
			httpsess_flush(hreq->hsess); /* enforce sending of enqueued packets:
			                                we have no new data for now */
			err = ERR_OK;
			goto out; /* we need to wait for completion */
		}
	}

	/* is the available chunk the one that we want to send out? */
	if (unlikely(cur_chk != hreq->f.cce[idx]->addr)) {
		printd("[idx=%u] buffer cannot be used yet. client did not acknowledge yet\n", idx);
		goto out;
	}

	/* is the chunk to process ready now? */
	if (unlikely(!shfs_aio_is_done(hreq->f.cce_t))) {
		printd("[idx=%u] current chunk %"PRIchk" is not ready yet\n", idx, cur_chk);
		httpsess_flush(hreq->hsess); /* enforce sending of enqueued packets:
		                                we have no new data for now */
		goto out; /* we need to wait for completion */
	}
	/* is the chunk to process valid? (it might be invalid due to I/O erros) */
	if (unlikely(hreq->f.cce[idx]->invalid)) {
		printd("[idx=%u] requested chunk is INVALID! (I/O error)\n", idx);
		err = ERR_ABRT;
		goto out;
	}

	chk_off = shfs_volchkoff_foff(hreq->fd, foff);
	left = min(shfs_vol.chunksize - chk_off, hreq->rlen - roff);
	slen = left;
	err  = httpsess_write(hreq->hsess,
	                      ((uint8_t *) (hreq->f.cce[idx]->buffer)) + chk_off,
	                      &slen, TCP_WRITE_FLAG_MORE);
	*sent += slen;
	if (unlikely(err != ERR_OK || !slen)) {
		printd("[idx=%u] sending failed, aborting this round\n", idx);
		httpsess_flush(hreq->hsess); /* send buffer might be full:
		                                we need to wait for ack */
		goto out;
	}
	printd("[idx=%u] sent %u bytes (%"PRIu64"-%"PRIu64", left on this chunk: %"PRIu64", available on sndbuf: %"PRIu32", sndqueuelen: %"PRIu16", infly: %"PRIu64")\n",
	        idx, slen, chk_off, chk_off + slen, left - slen, tcp_sndbuf(hreq->hsess->tpcb),
	        tcp_sndqueuelen(hreq->hsess->tpcb), (uint64_t) hreq->hsess->sent_infly);

	/* are we done with this chunkbuffer and there is still data that needs to be sent?
	 *  -> continue with next buffer */
	if (slen == left && *sent < hreq->rlen) {
		printd("[idx=%u] switch to next buffer [idx=%u]\n", idx, httpreq_fio_nextidx(hreq, idx));
		idx = httpreq_fio_nextidx(hreq, idx);
		roff += slen; /* new offset */
		foff += slen;
		cur_chk = shfs_volchk_foff(hreq->fd, foff);
		goto next;
	}

 out:
	hreq->f.cce_idx = idx;
	return err;
}

static inline void httpreq_fio_init(struct http_req *hreq)
{
	register unsigned i;

	hreq->f.cce_idx = 0;
	if (shfs_mounted)
		hreq->f.cce_max_nb = httpreq_fio_nb_buffers(shfs_vol.chunksize);
	else
		hreq->f.cce_max_nb = HTTPREQ_FIO_MAXNB_BUFFERS; /* a file open (shfs_open()) will fail when building response hdr
								 * there will be no file contents served */
	hreq->f.cce_idx_ack = hreq->f.cce_max_nb - 1;
	for (i = 0; i < hreq->f.cce_max_nb; ++i)
		hreq->f.cce[i] = NULL;
	hreq->f.cce_t = NULL;

	BUG_ON(hreq->f.cce_max_nb > HTTPREQ_FIO_MAXNB_BUFFERS);
}

static inline int httpreq_fio_build_hdr(struct http_req *hreq)
{
	size_t nb_slines = http_sendhdr_get_nbslines(&hreq->response.hdr);
	size_t nb_dlines = http_sendhdr_get_nbdlines(&hreq->response.hdr);
	char strsbuf[64];
	int ret;

	httpreq_fio_init(hreq);

	shfs_fio_size(hreq->fd, &hreq->f.fsize);

	/* File range requested? */
	hreq->response.code = 200;	/* 200 OK */
	hreq->f.rfirst = 0;
	hreq->f.rlast  = hreq->f.fsize - 1;
	ret = http_recvhdr_findfield(&hreq->request.hdr, "range");
	if (ret >= 0) {
		/* Because range requests require different answer codes
		 * (e.g., 206 OK or 416 EINVAL), we need to check the
		 * range request here already.
		 * http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.16 */
		hreq->response.code = 416;
		if (strncasecmp("bytes=", hreq->request.hdr.line[ret].value.b, 6) == 0) {
			uint64_t rfirst;
			uint64_t rlast;

			ret = sscanf(hreq->request.hdr.line[ret].value.b + 6,
			             "%"PRIu64"-%"PRIu64,
			             &rfirst, &rlast);
			if (ret == 1) {
				/* only rfirst specified */
				if (rfirst < hreq->f.rlast) {
					hreq->f.rfirst = rfirst;
					hreq->response.code = 206;
				}
			} else if (ret == 2) {
				/* both, rfirst and rlast, specified */
				if ((rfirst < rlast) &&
				    (rfirst < hreq->f.rlast) &&
				    (rlast <= hreq->f.rlast)) {
					hreq->f.rfirst = rfirst;
					hreq->f.rlast = rlast;
					hreq->response.code = 206;
				}
			}
		}

		if (hreq->response.code == 416) {
			/* (parsing/out of range) error: response with 416 error header */
			printd("Could not parse range request\n");
			goto err416_hdr;
		}

		printd("Client requested range of element: %"PRIu64"-%"PRIu64"\n",
		        hreq->f.rfirst, hreq->f.rlast);
	}

	/* HTTP OK [first line] (code can be 216 or 200) */
	if (hreq->response.code == 206)
		http_sendhdr_add_shdr(&hreq->response.hdr, &nb_slines,
				      HTTP_SHDR_206(hreq->request.http_major, hreq->request.http_minor));
	else
		http_sendhdr_add_shdr(&hreq->response.hdr, &nb_slines,
				      HTTP_SHDR_200(hreq->request.http_major, hreq->request.http_minor));

	/* Accept range */
	http_sendhdr_add_shdr(&hreq->response.hdr, &nb_slines, HTTP_SHDR_ACC_BYTERANGE);

	/* MIME (by element or default) */
	shfs_fio_mime(hreq->fd, strsbuf, sizeof(strsbuf));
	if (strsbuf[0] == '\0')
		http_sendhdr_add_shdr(&hreq->response.hdr, &nb_slines,
				      HTTP_SHDR_DEFAULT_TYPE);
	else
		http_sendhdr_add_dline(&hreq->response.hdr, &nb_dlines,
				       "%s: %s\r\n", _http_dhdr[HTTP_DHDR_MIME], strsbuf);

	/* Content length */
	hreq->rlen = (hreq->f.rlast + 1) - hreq->f.rfirst;
	http_sendhdr_add_dline(&hreq->response.hdr, &nb_dlines,
			       "%s: %"PRIu64"\r\n", _http_dhdr[HTTP_DHDR_SIZE], hreq->rlen);

	/* Content range */
	if (hreq->response.code == 206)
		http_sendhdr_add_dline(&hreq->response.hdr, &nb_dlines,
				       "%s%"PRIu64"-%"PRIu64"/%"PRIu64"\r\n",
				       _http_dhdr[HTTP_DHDR_RANGE],
				       hreq->f.rfirst, hreq->f.rlast, hreq->f.fsize);

	/* Initialize volchk range values for I/O */
	if (hreq->rlen != 0) {
		hreq->f.volchk_first = shfs_volchk_foff(hreq->fd, hreq->f.rfirst);                     /* first volume chunk of file */
		hreq->f.volchk_last  = shfs_volchk_foff(hreq->fd, hreq->f.rlast + hreq->f.rfirst);       /* last volume chunk of file */
		hreq->f.volchkoff_first = shfs_volchkoff_foff(hreq->fd, hreq->f.rfirst);               /* first byte in first chunk */
		hreq->f.volchkoff_last  = shfs_volchkoff_foff(hreq->fd, hreq->f.rlast + hreq->f.rfirst); /* last byte in last chunk */
	}
 out:
	http_sendhdr_set_nbslines(&hreq->response.hdr, nb_slines);
	http_sendhdr_set_nbdlines(&hreq->response.hdr, nb_dlines);
	return 0;

 err416_hdr:
	/* 416 Range request error */
	hreq->response.code = 416;
	http_sendhdr_add_shdr(&hreq->response.hdr, &nb_slines,
			      HTTP_SHDR_416(hreq->request.http_major, hreq->request.http_minor));
	http_sendhdr_add_dline(&hreq->response.hdr, &nb_dlines,
			       "%s: %"PRIu64"\r\n", _http_dhdr[HTTP_DHDR_SIZE], 0);
	hreq->type = HRT_NOMSG;
	goto out;
}

static inline void httpreq_fio_close(struct http_req *hreq)
{
	register unsigned i;

	for (i = 0; i < hreq->f.cce_max_nb; ++i) {
		if (i == hreq->f.cce_idx && hreq->f.cce[i]) {
			shfs_cache_release_ioabort(hreq->f.cce[i], hreq->f.cce_t);
		} else if (hreq->f.cce[i]) {
			shfs_cache_release(hreq->f.cce[i]);
			hreq->f.cce[i] = NULL;
		}
	}
}

static inline void httpreq_ack_fio(struct http_req *hreq, size_t acked)
{
	register size_t roff, foff;
	register chk_t start_chk;
	register chk_t end_chk;
	register chk_t nb_chk;
	register chk_t i;
	register unsigned int idx;
	struct shfs_cache_entry *cce;

	roff = hreq->alen - acked; /* already ack'ed offset in request */
	foff = roff + hreq->f.rfirst;  /* offset in file */
	start_chk = shfs_volchk_foff(hreq->fd, foff);
	end_chk  = shfs_volchk_foff(hreq->fd, foff + acked);

	printd("Client acknowledged %"PRIu64" bytes from buffers\n", (uint64_t) acked);
	if (start_chk < end_chk) {
		/* release cache buffers */
		nb_chk = end_chk - start_chk;
		idx = hreq->f.cce_idx_ack;
		for (i = 0; i < nb_chk; ++i) {
			idx = httpreq_fio_nextidx(hreq, idx);
			printd("[idx=%u] Releasing buffer because data got acknowledged\n", idx);
			cce = hreq->f.cce[idx];
			BUG_ON(cce->addr != start_chk + i);
			hreq->f.cce[idx] = NULL;
			shfs_cache_release(cce); /* calls notify_retry */
		}
		hreq->f.cce_idx_ack = idx;
	}
}

#endif
