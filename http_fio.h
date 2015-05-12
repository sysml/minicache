/*
 * thpHTTP - A tiny high performance HTTP server for Mini-OS
 *  This HTTP server is based on http_parser.
 *
 * Copyright(C) 2014-2015 NEC Laboratories Europe. All rights reserved.
 *                        Simon Kuenzer <simon.kuenzer@neclab.eu>
 */
#ifndef _HTTP_FIO_H_
#define _HTTP_FIO_H_

#include "http_defs.h"

#define httpreq_fio_nb_buffers(chunksize)  (max((DIV_ROUND_UP(HTTPREQ_TCP_MAXSNDBUF, (size_t) chunksize)), 2))

void httpreq_fio_aiocb(SHFS_AIO_TOKEN *t, void *cookie, void *argp);

/* async SHFS I/O */
#define httpreq_fio_nextidx(fstate, idx) \
        ((idx + 1) % (hreq)->f.cce_max_nb)

static inline int httpreq_fio_aioreq(struct http_req *hreq, chk_t addr, unsigned int cce_idx)
{
	/* gets called whenever an async I/O request completed */
	int ret;

	BUG_ON(hreq->f.cce_t);

	ret = shfs_cache_aread(addr,
	                       httpreq_fio_aiocb,
	                       hreq,
	                       NULL,
	                       &hreq->f.cce[cce_idx],
	                       &hreq->f.cce_t);
	if (unlikely(ret < 0)) {
		printd("failed to perform request for [cce_idx=%u]: %d\n", cce_idx, ret);
		return ret;
	}
	printd("request set up for [cce_idx=%u]\n", cce_idx);
	return ret;
}

static inline err_t httpreq_write_fio(struct http_req *hreq, size_t *sent)
{
	register size_t roff, foff;
	register tcpwnd_size_t avail;
	register uint16_t left;
	register chk_t  cur_chk;
	register size_t chk_off;
	register unsigned int idx;
	uint16_t slen;
	err_t err;
	int ret;

	idx = hreq->f.cce_idx;
	roff = *sent; /* offset in request */
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
			httpsess_flush(hreq->hsess); /* enforce sending of enqueued packets:
			                                we have no new data for now */
			err = ERR_OK;
			goto err_abort;
		} else if (unlikely(ret < 0)) {
			/* Read ERROR happened -> abort */
			printd("[idx=%u] fatal read error (%d): aborting...\n", idx, ret);
			httpsess_flush(hreq->hsess); /* enforce sending of enqueued packets:
			                                we have no new data for now */
			err = ERR_ABRT;
			goto err_abort;
		} else if (ret == 1) {
			/* current request is not done yet,
			 * we need to wait. httpsess_response
			 * will be recalled from within callback */
			printd("[idx=%u] requested chunk is not ready yet\n", idx);
			httpsess_flush(hreq->hsess); /* enforce sending of enqueued packets:
			                                we have no new data for now */
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
		printd("[idx=%u] requested chunk is not ready yet\n", idx);
		httpsess_flush(hreq->hsess); /* enforce sending of enqueued packets:
		                                we have no new data for now */
		goto out;
	}
	/* is the chunk to process valid? (it might be invalid due to I/O erros) */
	if (unlikely(hreq->f.cce[idx]->invalid)) {
		printd("[idx=%u] requested chunk is INVALID! (I/O error)\n", idx);
		err = ERR_ABRT;
		goto err_abort;
	}

	/* send out data from chk buffer that is loaded already */
	avail = tcp_sndbuf(hreq->hsess->tpcb);
	if (unlikely(avail == 0)) {
		/* we need to wait for free space on tcp sndbuf
		 * httpsess_response is recalled when client has
		 * acknowledged its received data */
		printd("[idx=%u] tcp send buffer is full, retry it next round\n", idx);
		goto out;
	}
	chk_off = shfs_volchkoff_foff(hreq->fd, foff);
	left = (uint16_t) min3(UINT16_MAX, shfs_vol.chunksize - chk_off, hreq->rlen - roff);
	slen = (uint16_t) min3(UINT16_MAX, avail, left);
	err  = httpsess_write(hreq->hsess,
	                      ((uint8_t *) (hreq->f.cce[idx]->buffer)) + chk_off,
	                      &slen, TCP_WRITE_FLAG_MORE);
	*sent += (size_t) slen;
	if (unlikely(err != ERR_OK)) {
		printd("[idx=%u] sending failed, aborting this round\n", idx);
		httpsess_flush(hreq->hsess); /* send buffer might be full:
		                                we need to wait for ack */
		goto out;
	}
	printd("[idx=%u] sent %u bytes (%"PRIu64"-%"PRIu64", chunksize: %lu, left on this chunk: %lu, available on sndbuf: %"PRIu16", sndqueuelen: %"PRIu16", infly: %"PRIu64")\n",
	        idx, slen, chk_off, chk_off + slen, shfs_vol.chunksize, left - (size_t) slen, avail - slen,
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

 err_abort:
	return err;
}

static inline void httpreq_fio_init(struct http_req *hreq)
{
	register unsigned i;

	hreq->f.cce_idx = 0;
	if (shfs_mounted)
		hreq->f.cce_max_nb = httpreq_fio_nb_buffers(shfs_vol.chunksize);
	else
		hreq->f.cce_max_nb = HTTPREQ_FIO_MAXNB_BUFFERS; /* shfs_open() will fail later --> no file content will be served */
	hreq->f.cce_idx_ack = hreq->f.cce_max_nb - 1;
	for (i = 0; i < hreq->f.cce_max_nb; ++i)
		hreq->f.cce[i] = NULL;
	hreq->f.cce_t = NULL;
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
			printd("[idx=%u] Releasing buffer because data got acknowledged\n", idx);
			idx = httpreq_fio_nextidx(hreq, idx);
			cce = hreq->f.cce[idx];
			BUG_ON(cce->addr != start_chk + i);
			hreq->f.cce[idx] = NULL;
			shfs_cache_release(cce); /* calls notify_retry */
		}
		hreq->f.cce_idx_ack = idx;
	}
}

#endif
