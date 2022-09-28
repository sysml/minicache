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

#include "http_link.h"

static err_t httplink_request(struct http_req_link_origin *o);
static err_t httplink_write(struct http_req_link_origin *o, const void* buf, size_t *len, uint8_t apiflags);
static int httplink_recv_data(http_parser *parser, const char *c, size_t len);
static int httplink_recv_hdrcomplete(http_parser *parser);
static int httplink_recv_datacomplete(http_parser *parser);

static http_parser_settings _httplink_parser_settings = {
	.on_header_field = httpparser_recvhdr_field,
	.on_header_value = httpparser_recvhdr_value,
	.on_headers_complete = httplink_recv_hdrcomplete,
	.on_body = httplink_recv_data,
	.on_message_complete = httplink_recv_datacomplete
};

typedef int (*http_data_cb) (http_parser*, const char *at, size_t length);
typedef int (*http_cb) (http_parser*);

int httplink_init(struct http_srv *hs)
{
  hs->link_pool = alloc_simple_mempool(HTTP_MAXNB_LINKS, sizeof(struct http_req_link_origin));
  if (!hs->link_pool)
    return -ENOMEM;

  hs->nb_links = 0;
  hs->max_nb_links = HTTP_MAXNB_LINKS;
  dlist_init_head(hs->links);

  return 0;
}

void httplink_exit(struct http_srv *hs)
{
  BUG_ON(hs->nb_links != 0);

  free_mempool(hs->link_pool);
}

#if LWIP_DNS
void httpreq_link_dnscb(const char *name, ip_addr_t *ipaddr, void *argp)
{
	struct http_req *hreq = (struct http_req *) argp;
	struct http_req_link_origin *o = hreq->l.origin;

	if (!((ipaddr) && (ipaddr->addr))) {
		printd("Could not resolve '%s'\n", name);
		o->sstate = HRLOS_ERROR;
	} else {
		printd("Name resolution for '%s' was successful\n", name);
		o->rip.addr = ipaddr->addr;
		o->sstate = HRLOS_CONNECT;
	}

	httpsess_respond(hreq->hsess);
}
#endif

static inline void httplink_build_reqhdr(struct http_req_link_origin *o)
{
#ifdef HTTP_DEBUG
	register unsigned l;
#endif
	unsigned nb_slines = 0;
	unsigned nb_dlines = 0;
	char strsbuf[64];
	char strlbuf[128];
	size_t reqlen;
  
	strshfshost(strsbuf, sizeof(strsbuf),
		    shfs_fio_link_rhost(o->fd));
	shfs_fio_link_rpath(o->fd, strlbuf, sizeof(strlbuf));

	reqlen = snprintf(o->request.req, sizeof(o->request.req),
			  "GET /%s HTTP/1.1\r\n", strlbuf);
	http_sendhdr_add_sline(&o->request.hdr, &nb_slines, o->request.req, reqlen);
	http_sendhdr_add_shdr(&o->request.hdr, &nb_slines, HTTP_SHDR_CONN_CLOSE);
	http_sendhdr_add_shdr(&o->request.hdr, &nb_slines, HTTP_SHDR_USERAGENT);
	if (shfs_fio_link_rport(o->fd) == 80) {
		http_sendhdr_add_dline(&o->request.hdr, &nb_dlines,
				       "%s: %s\r\n", _http_dhdr[HTTP_DHDR_HOST],
				       strsbuf, strlbuf);
	} else {
		http_sendhdr_add_dline(&o->request.hdr, &nb_dlines,
				       "%s: %s:%"PRIu16"\r\n", _http_dhdr[HTTP_DHDR_HOST],
				       strsbuf, shfs_fio_link_rport(o->fd), strlbuf);
	}
	http_sendhdr_add_dline(&o->request.hdr, &nb_dlines,
			       "%s: 0\r\n", _http_dhdr[HTTP_DHDR_ICYMETADATA]);

	http_sendhdr_set_nbslines(&o->request.hdr, nb_slines);
	http_sendhdr_set_nbdlines(&o->request.hdr, nb_dlines);
	o->request.hdr_total_len = http_sendhdr_calc_totallen(&o->request.hdr);
	o->request.hdr_acked_len = 0;

#ifdef HTTP_DEBUG
	printd("Request:\n");
	for (l = 0; l < o->request.hdr.nb_slines; ++l) {
		printd("   %s",
		       o->request.hdr.sline[l].b);
	}
	for (l = 0; l < o->request.hdr.nb_dlines; ++l) {
		printd("   %s",
		       o->request.hdr.dline[l].b);
	}
#endif
}

err_t httplink_connected(void *argp, struct tcp_pcb * tpcb, err_t err)
{
  struct http_req_link_origin *o = (struct http_req_link_origin *) argp;

  printd("Connection of origin %p established\n", o);
  httplink_build_reqhdr(o);
 
  /* switch to request phase */
  o->cstate = HRLOC_REQUEST;
  o->sstate = HRLOS_WAIT_RESPONSE;
  o->timeout = HTTP_LINK_RESPONSE_TIMEOUT;
  return httplink_request(o);
}


err_t httplink_close(struct http_req_link_origin *o, enum http_sess_close type)
{
	err_t err;

	if (!o->tpcb)
		return ERR_OK;

	printd("%s origin %p (caller: 0x%x)\n",
	        (type == HSC_ABORT ? "Aborting" :
	         (type == HSC_CLOSE ? "Closing" : "Killing")),
	        o, get_caller());
	o->cstate = HRLOC_ERROR;
	o->sstate = HRLOS_ERROR;

	/* disable tcp connection */
	tcp_sent(o->tpcb, NULL);
	tcp_recv(o->tpcb, NULL);
	tcp_sent(o->tpcb, NULL);
	tcp_err (o->tpcb, NULL);
	tcp_poll(o->tpcb, NULL, 0);
	tcp_arg (o->tpcb, NULL);

	/* terminate connection */
	if (o->tpcb) {
		switch (type) {
		case HSC_CLOSE:
			err = tcp_close(o->tpcb);
			if (likely(err == ERR_OK))
				break;
		case HSC_ABORT:
			tcp_abort(o->tpcb);
			err = ERR_ABRT; /* lwip callback functions need to be notified */
			break;
		default: /* HSC_KILL */
			err = ERR_OK;
			break;
		}
	}
	o->tpcb = NULL;

	return err;
}

static err_t httplink_request(struct http_req_link_origin *o)
{
	err_t err = ERR_OK;

	//BUG_ON(o->cstate != HRLOC_REQUEST);

	switch (o->cstate) {
	case HRLOC_REQUEST:
		err = http_sendhdr_write(&o->request.hdr, &o->sent,
					 (tcpwrite_fn_t) httplink_write, (void *) o);
		if (unlikely(err != ERR_OK && err != ERR_MEM))
			goto err_close;
		if (o->sent == o->request.hdr_total_len) {
			/* we are done -> switch to receive mode */
			o->cstate = HRLOC_GETRESPONSE;
			o->timeout = HTTP_LINK_RESPONSE_TIMEOUT;
		}
		break;

	case HRLOC_ERROR:
		/* state error */
		goto err_close;

	default:
		break; /* do nothing */
	}

	return ERR_OK;

 err_close:
	httplink_close(o, HSC_ABORT);
	return err;
}

static err_t httplink_write(struct http_req_link_origin *o, const void* buf, size_t *len, uint8_t apiflags)
{
	struct tcp_pcb *pcb = o->tpcb;
	register size_t l, s;
	uint16_t slen;
	err_t err;

	s = 0;
	l = *len;
	err = ERR_OK;

 try_next:
	slen = (uint16_t) min3(l, tcp_sndbuf(pcb), UINT16_MAX);
	if (!slen)
		goto out;

 try_again:
	printd("tcp_write(buf=@%p, slen=%"PRIu16", left=%"PRIu64", sndbuf=%"PRIu32", sndqueuelen=%"PRIu16")\n",
	       buf, slen, l, (uint32_t) tcp_sndbuf(pcb), (uint16_t) tcp_sndqueuelen(pcb));
	err = tcp_write(pcb, buf, slen, apiflags);
	if (err == ERR_OK) {
		s += slen;
		l -= slen;
		buf = (const void *) ((uintptr_t) buf + slen);
		goto try_next;
	}
	if (err == ERR_MEM) {
		if (!tcp_sndbuf(pcb) ||
		    (tcp_sndqueuelen(pcb) >= TCP_SND_QUEUELEN)) {
			goto out; /* no need to try smaller sizes, send buffers are full */
		} else {
			slen >>= 1; /* l /= 2 */
			goto try_again;
		}
	}

 out:
	o->sent_infly += s;
	*len = s;
	return err;
}

err_t httplink_sent(void *argp, struct tcp_pcb *tpcb, uint16_t len)
{
	struct http_req_link_origin *o = (struct http_req_link_origin *) argp;
	size_t left;

	printd("ACK for origin %p\n", o);
	o->sent_infly -= len;

	if (o->sstate == HRLOS_ERROR || o->cstate == HRLOC_ERROR)
		httplink_close(o, HSC_ABORT); /* drop connection */

	/* ack request */
	if (o->request.hdr_acked_len < o->request.hdr_total_len) {
		left = o->request.hdr_total_len - o->request.hdr_acked_len;
		if (left > len)
			o->request.hdr_acked_len += len;
		else
			o->request.hdr_acked_len += left;

		return httplink_request(o);
	}

	return ERR_OK;
}

err_t httplink_recv(void *argp, struct tcp_pcb *tpcb, struct pbuf *p, err_t err)
{
	struct http_req_link_origin *o = (struct http_req_link_origin *) argp;
	struct pbuf *q;
	size_t plen;
	err_t ret = ERR_OK;

	if (unlikely(!p || err != ERR_OK)) {
		/* receive error: kill connection */
		printd("Unexpected session error (p=%p, err=%d)\n", p, err);
		if (p) {
			tcp_recved(tpcb, p->tot_len);
			pbuf_free(p);
		}
		return httplink_close(o, HSC_ABORT);
	}

	switch (o->cstate) {
	case HRLOC_GETRESPONSE:
	case HRLOC_CONNECTED:
		/* feed parser */
		for (q = p; q != NULL; q = q->next) {
			plen = http_parser_execute(&o->parser, &_httplink_parser_settings,
			                           q->payload, q->len);
			if (unlikely(plen != q->len)) {
				/* less data was parsed: this happens only when
				 * there was a parsing error */
				printd("HTTP protocol parsing error: Dropping connection...\n");
				ret = httplink_close(o, HSC_CLOSE);
				goto out;
			}
		}

		/* inform clients that new data has arrived (only when PSH flag is set) */
		if ((p->flags & PBUF_FLAG_PUSH) && (o->sstate==HRLOS_CONNECTED))
			httplink_notify_clients(o);
		break;

	default:
		/* unexpected data received */
		printd("Unexpected supported HTTP protocol upgrade requested: Dropping connection...\n");
		ret = httplink_close(o, HSC_CLOSE);
		goto out;
	}

	tcp_recved(tpcb, p->tot_len);

 out:
	pbuf_free(p);
	return ret;
}

void httplink_error(void *argp, err_t err)
{
	struct http_req_link_origin *o = (struct http_req_link_origin *) argp;

	printd("Killing origin connection %p due to error: %d\n", o, err);
	httplink_close(o, HSC_KILL); /* drop connection */
}

err_t httplink_poll(void *argp, struct tcp_pcb *tpcb)
{
	struct http_req_link_origin *o = (struct http_req_link_origin *) argp;

	printd("Polling origin connection %p\n", o);
	switch (o->sstate) {
	case HRLOS_CONNECT:
	case HRLOS_WAIT_RESPONSE:
		--o->timeout;
		if (o->timeout == 0) {
			printd("Timeout expired\n", o);
			o->sstate = HRLOS_ERROR;
			httplink_notify_clients(o);
		}
		break;

	case HRLOS_CONNECTED: /* time out when receiving data */
		if (o->to_pos != o->pos) {
			/* reset timeout */
			o->timeout = HTTP_LINK_RECEIVE_TIMEOUT;
			o->to_pos  = o->pos;
			break;
		}

		--o->timeout;
		if (o->timeout == 0) {
			printd("Receive timeout expired\n", o);
			o->sstate = HRLOS_ERROR;
			httplink_notify_clients(o);
		}
		break;

	default:
		break;
	}
	return ERR_OK;
}

/*
 * Following functions get called by parser when incoming message is decoded
 */
static int httplink_recv_hdrcomplete(http_parser *parser)
{
	struct http_req_link_origin *o = container_of(parser, struct http_req_link_origin, parser);
#ifdef HTTP_DEBUG
	unsigned l;
#endif
	enum lftype lft;
	int ret;

	/* first we null-terminate all received header fields */
	http_recvhdr_terminate(&o->response.hdr);

#ifdef HTTP_DEBUG
	printd("origin %p: Server replied:\n", o);
	printd("   HTTP/%hu.%hu %d\n",
	       parser->http_major,
	       parser->http_minor,
	       parser->status_code);
	for (l = 0; l < o->response.hdr.nb_lines; ++l) {
		printd("   %s: %s\n",
		       o->response.hdr.line[l].field.b,
		       o->response.hdr.line[l].value.b);
	}
#endif

	/* did server respond with status code 200? */
	if (parser->status_code != 200) {
		printd("Server of origin %p did not return 200: Closing connection...\n", o);
		httplink_close(o, HSC_CLOSE);
		httplink_notify_clients(o);
		return 0;
	}

	/* search for mime type in response */
	ret = http_recvhdr_findfield(&o->response.hdr, _http_dhdr[HTTP_DHDR_MIME]);
	if (ret >= 0) {
		o->response.mime = o->response.hdr.line[ret].value.b;
		lft = mime_to_lftype(o->response.mime);
		if (!lft) {
			printd("origin %p: MIME type unknown to join parser, use default format\n", o);
			lft = HTTPLINK_DEFAULT_FORMAT;
		}
	} else  {
		printd("origin %p: No MIME type detected, use default format for join parser\n", o);
		lft = HTTPLINK_DEFAULT_FORMAT;
	}

	/* init format parser */
	printd("origin %p: Initialize join parser with format id %d\n", o, lft);
	init_lformat(&o->lfs, lft, 0);

	/* switch to connected phase */
	o->sstate = HRLOS_CONNECTED;
	o->cstate = HRLOC_CONNECTED;
	o->to_pos = o->pos;
	o->timeout = HTTP_LINK_RECEIVE_TIMEOUT;

	/* we will announce to clients later since
	 * we might retrieve some data already */
	//httplink_notify_clients(o);
	return 0;
}

static int httplink_recv_datacomplete(http_parser *parser)
{
	struct http_req_link_origin *o = container_of(parser, struct http_req_link_origin, parser);

	/* switch to end of stream phase */
	httplink_close(o, HSC_CLOSE);
	o->sstate = HRLOS_EOF;
	httplink_notify_clients(o);

	return 0;
}

static int httplink_recv_data(http_parser *parser, const char *c, size_t len)
{
	struct http_req_link_origin *o = container_of(parser, struct http_req_link_origin, parser);
	register size_t avail, pos;
	register uintptr_t bffr_off;
	register unsigned int idx;
	size_t rlen;

	pos = o->pos;
	idx = o->cce_idx;

	while (len) {
		//idx = (pos / shfs_vol.chunksize) % o->cce_max_idx;
		bffr_off = pos % shfs_vol.chunksize;
		avail = shfs_vol.chunksize - bffr_off;
		rlen = min(len, avail);

		printd("Save %"PRIu64" bytes to buffer %u (%p) at offset %"PRIu64" (pos=%"PRIu64")\n",
		       rlen, idx, o->cce[idx]->buffer, bffr_off, pos);
		//printh(c, rlen);
		MEMCPY((void *)(((uintptr_t) o->cce[idx]->buffer) + bffr_off), c, rlen);
		lformat_parse(&o->lfs, (void *)(((uintptr_t) o->cce[idx]->buffer) + bffr_off), rlen); /* updates join */

		pos += rlen;
		len -= rlen;
		c   += rlen;
		if (rlen == avail) {
			/* point to next buffer is current is full */
			idx = (idx + 1) % o->cce_max_idx;
			if (idx > o->cce_max_idx)
				o->lower_limit += shfs_vol.chunksize;
		}
	}

	o->pos = pos;
	o->cce_idx = idx;
	return 0;
}
