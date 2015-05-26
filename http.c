/*
 * HTTP - A tiny high performance HTTP server for Mini-OS
 *  This HTTP server is based on http_parser (from nginx)
 *  The filesystem backend SHFS is directly bound to it
 *
 * Copyright(C) 2014 NEC Laboratories Europe. All rights reserved.
 *                   Simon Kuenzer <simon.kuenzer@neclab.eu>
 */
#if defined HAVE_SHELL && defined HTTP_INFO
#include "shell.h"
#endif

#include "http_defs.h"
#include "http_data.h"
#include "http_fio.h"
#include "http_link.h"
#include "http.h"

struct http_srv *hs = NULL;

static err_t httpsess_accept (void *argp, struct tcp_pcb *new_tpcb, err_t err);
static err_t httpsess_close  (struct http_sess *hsess, enum http_sess_close type);
static err_t httpsess_sent   (void *argp, struct tcp_pcb *tpcb, uint16_t len);
static err_t httpsess_recv   (void *argp, struct tcp_pcb *tpcb, struct pbuf *p, err_t err);
static void  httpsess_error  (void *argp, err_t err);
static err_t httpsess_poll   (void *argp, struct tcp_pcb *tpcb);
static err_t httpsess_acknowledge(struct http_sess *hsess, size_t len);
static int httprecv_req_complete(struct http_parser *parser);
static int httprecv_hdr_url(struct http_parser *parser, const char *buf, size_t len);
#if defined HAVE_SHELL && defined HTTP_INFO
static int shcmd_http_info(FILE *cio, int argc, char *argv[]);
#endif

static http_parser_settings _http_parser_settings = {
	.on_message_begin = NULL,
	.on_url = httprecv_hdr_url,
	.on_status = NULL,
	.on_header_field = httpparser_recvhdr_field,
	.on_header_value = httpparser_recvhdr_value,
	.on_headers_complete = NULL,
	.on_body = NULL,
	.on_message_complete = httprecv_req_complete
};

int init_http(uint16_t nb_sess, uint32_t nb_reqs)
{
	err_t err;
	int ret = 0;

	hs = target_malloc(CACHELINE_SIZE, sizeof(*hs));
	if (!hs) {
		ret = -ENOMEM;
		goto err_out;
	}
	hs->max_nb_sess = nb_sess;
	hs->nb_sess = 0;
	hs->max_nb_reqs = nb_reqs;
	hs->nb_reqs = 0;

	/* allocate session pool */
	hs->sess_pool = alloc_simple_mempool(hs->max_nb_sess, sizeof(struct http_sess));
	if (!hs->sess_pool) {
		ret = -ENOMEM;
		goto err_free_hs;
	}

	/* allocate request pool */
	hs->req_pool = alloc_simple_mempool(hs->max_nb_reqs, sizeof(struct http_req));
	if (!hs->req_pool) {
		ret = -ENOMEM;
		goto err_free_sesspool;
	}

	/* initialize http link system */
	ret = httplink_init(hs);
	if (ret < 0)
		goto err_free_reqpool;

	/* register TCP listener */
	hs->tpcb = tcp_new();
	if (!hs->tpcb) {
		ret = -ENOMEM;
		goto err_exit_link;
	}
	err = tcp_bind(hs->tpcb, IP_ADDR_ANY, HTTP_LISTEN_PORT);
	if (err != ERR_OK) {
		ret = -err;
		goto err_free_tcp;
	}
	hs->tpcb = tcp_listen(hs->tpcb);
	tcp_arg(hs->tpcb, hs);
	tcp_accept(hs->tpcb, httpsess_accept); /* register session accept */

	/* init session list */
	hs->hsess_head = NULL;
	hs->hsess_tail = NULL;

	/* wait for I/O retry list */
	dlist_init_head(hs->ioretry_chain);

	printd("HTTP server %p initialized\n", hs);
#if defined HAVE_SHELL && defined HTTP_INFO
	shell_register_cmd("http-info", shcmd_http_info);
#endif
	return 0;

 err_free_tcp:
	tcp_abort(hs->tpcb);
 err_exit_link:
	httplink_exit(hs);
 err_free_reqpool:
	free_mempool(hs->req_pool);
 err_free_sesspool:
	free_mempool(hs->sess_pool);
 err_free_hs:
	target_free(hs);
 err_out:
	return ret;
}

void exit_http(void)
{
	/* terminate connections that are still open */
	while(hs->hsess_head) {
		printd("Closing session %p...\n", hs->hsess_head);
		httpsess_close(hs->hsess_head, HSC_CLOSE);
	}
	BUG_ON(hs->nb_reqs != 0);
	BUG_ON(hs->nb_sess != 0);

	tcp_close(hs->tpcb);
	httplink_exit(hs);
	free_mempool(hs->req_pool);
	free_mempool(hs->sess_pool);
	target_free(hs);
	hs = NULL;
}

/*******************************************************************************
 * Session + Request handling
 ******************************************************************************/
#define httpsess_reset_keepalive(hsess) \
	do { \
		(hsess)->keepalive_timer = HTTP_KEEPALIVE_TIMEOUT; \
	} while(0)
#define httpsess_halt_keepalive(hsess) \
	do { \
		(hsess)->keepalive_timer = -1; \
	} while(0)

/* gets called whenever it is worth
 * to retry an failed file I/O operation (with EAGAIN) */
void http_poll_ioretry(void) {
	struct http_sess *hsess;
	struct http_sess *hsess_next;

	if (unlikely(!hs))
		return; /* no active http server */

	hsess = dlist_first_el(hs->ioretry_chain, struct http_sess);
	/* clear head so that a new list is created
	 * This avoids the the case that within a callback the elements gets
	 * appanded to the list over an over again */
	dlist_init_head(hs->ioretry_chain);
	while (hsess) {
		hsess_next = dlist_next_el(hsess, ioretry_chain);

		/* "unlink" this element from the list because
		 * the head is released already -> we need to do a list cleanup */
		hsess->ioretry_chain.next = NULL;
		hsess->ioretry_chain.prev = NULL;

		printd("Retrying I/O on session %p\n", hsess);
		httpsess_respond(hsess); /* can register itself to the new list */

		hsess = hsess_next; /* next element */
	}
}

static inline struct http_req *httpreq_open(struct http_sess *hsess)
{
	struct mempool_obj *hrobj;
	struct http_req *hreq;

	hrobj = mempool_pick(hsess->hsrv->req_pool);
	if (!hrobj)
		return NULL;
	hreq = hrobj->data;
	hreq->pobj = hrobj;
	hreq->hsess = hsess;
	hreq->next = NULL;

	hreq->state = HRS_PARSING_HDR;
	hreq->type = HRT_UNDEF;
	http_recvhdr_reset(&hreq->request.hdr);
	hreq->request.url_len = 0;
	hreq->request.url_overflow = 0;
	hreq->request.url_argp = NULL;
	http_sendhdr_reset(&hreq->response.hdr);
	hreq->response.hdr_total_len = 0;
	hreq->response.hdr_acked_len = 0;
	hreq->response.ftr_acked_len = 0;
	hreq->smsg = NULL;
	hreq->fd = NULL;
	hreq->rlen = 0;
	hreq->alen = 0;
	hreq->is_stream = 0;
#if defined SHFS_STATS && defined SHFS_STATS_HTTP && defined SHFS_STATS_HTTP_DPC
	hreq->stats.dpc_i = 0;
#endif
	++hsess->hsrv->nb_reqs;
	return hreq;
}

static inline void httpreq_close(struct http_req *hreq)
{
	struct http_sess *hsess = hreq->hsess;

	printd("Closing request %p...\n", hreq);

	/* unlink session from ioretry chain if it was linked before */
	httpsess_unregister_ioretry(hreq->hsess);

	/* close open file */
	if (hreq->fd) {
		switch (hreq->type) {
		case HRT_FIOMSG:
			printd("Release request %p from file I/O\n", hreq);
			httpreq_fio_close(hreq);
			break;
		case HRT_LINKMSG:
			printd("Release request %p from link\n", hreq);
			httpreq_link_close(hreq);
			break;
		default:
			break;
		}
		shfs_fio_close(hreq->fd);
	}
	mempool_put(hreq->pobj);
	--hsess->hsrv->nb_reqs;
	printd("Request %p destroyed\n", hreq);
}

static err_t httpsess_accept(void *argp, struct tcp_pcb *new_tpcb, err_t err)
{
	struct mempool_obj *hsobj;
	struct http_sess *hsess;

	if (err != ERR_OK)
		goto err_out;
	hsobj = mempool_pick(hs->sess_pool);
	if (!hsobj) {
		err = ERR_MEM;
		goto err_out;
	}
	hsess = hsobj->data;
	hsess->pobj = hsobj;
	hsess->hsrv = hs;
	hsess->sent_infly = 0;

	/* setup request queue */
	hsess->cpreq = httpreq_open(hsess);
	if (!hsess->cpreq) {
		err = ERR_MEM;
		goto err_free_hsess;
	}
	hsess->rqueue_head = NULL;
	hsess->rqueue_tail = NULL;
	hsess->rqueue_len = 0;
	hsess->aqueue_head = NULL;
	hsess->aqueue_tail = NULL;
	hsess->retry_replychain = 0;
	hsess->_in_respond = 0;

	/* register tpcb */
	hsess->tpcb = new_tpcb;
	tcp_arg (hsess->tpcb, hsess); /* argp for callbacks */
	tcp_recv(hsess->tpcb, httpsess_recv); /* recv callback */
	tcp_sent(hsess->tpcb, httpsess_sent); /* sent ack callback */
	tcp_err (hsess->tpcb, httpsess_error); /* err callback */
	tcp_poll(hsess->tpcb, httpsess_poll, HTTP_POLL_INTERVAL); /* poll callback */
	tcp_setprio(hsess->tpcb, HTTP_TCP_PRIO);

	/* Turn on TCP Keepalive */
	hsess->tpcb->so_options |= SOF_KEEPALIVE;
	hsess->tpcb->keep_intvl = (HTTP_TCPKEEPALIVE_TIMEOUT * 1000);
	hsess->tpcb->keep_idle = (HTTP_TCPKEEPALIVE_IDLE * 1000);
	hsess->tpcb->keep_cnt = 1;

	/* init parser */
	hsess->parser.data = (void *) &hsess->cpreq->request.hdr;
	http_parser_init(&(hsess)->parser, HTTP_REQUEST);

	/* reset HTTP keep alive */
	httpsess_reset_keepalive((hsess));

	/* register session to session list */
	if (!hs->hsess_head) {
		hs->hsess_head = hsess;
		hsess->prev = NULL;
	} else {
		hs->hsess_tail->next = hsess;
		hsess->prev = hs->hsess_tail;
	}
	hsess->next = NULL;
	hs->hsess_tail = hsess;

	dlist_init_el(hsess, ioretry_chain);

	hsess->state = HSS_ESTABLISHED;
	++hs->nb_sess;
	printd("New HTTP session accepted on server %p "
		"(currently, there are %"PRIu16"/%"PRIu16" open sessions)\n",
		hs, hs->nb_sess, hs->max_nb_sess);
	return 0;

 err_free_hsess:
	mempool_put(hsobj);
 err_out:
	printd("Session establishment declined on server %p "
		"(currently, there are %"PRIu16"/%"PRIu16" open sessions)\n",
		hs, hs->nb_sess, hs->max_nb_sess);
	return err;
}

static err_t httpsess_close(struct http_sess *hsess, enum http_sess_close type)
{
	struct http_req *hreq;
	err_t err;

	ASSERT(hsess != NULL);

	printd("%s session %p (caller: 0x%x)\n",
	        (type == HSC_ABORT ? "Aborting" :
	         (type == HSC_CLOSE ? "Closing" : "Killing")),
	        hsess,
	        get_caller());
	hsess->state = -99999;

	/* disable tcp connection */
	tcp_arg(hsess->tpcb,  NULL);
	tcp_sent(hsess->tpcb, NULL);
	tcp_recv(hsess->tpcb, NULL);
	tcp_sent(hsess->tpcb, NULL);
	tcp_err(hsess->tpcb,  NULL);
	tcp_poll(hsess->tpcb, NULL, 0);

	/* close unserved requests */
	if (dlist_is_linked(hsess, hs->ioretry_chain, ioretry_chain))
		printd(" Session is linked to IORetry list, removing it\n");
	httpsess_unregister_ioretry(hsess);

	for (hreq = hsess->aqueue_head; hreq != NULL; hreq = hreq->next)
		httpreq_close(hreq);
	for (hreq = hsess->rqueue_head; hreq != NULL; hreq = hreq->next)
		httpreq_close(hreq);
	if (hsess->cpreq)
		httpreq_close(hsess->cpreq);

	/* terminate connection */
	switch (type) {
	case HSC_CLOSE:
		err = tcp_close(hsess->tpcb);
		if (likely(err == ERR_OK))
			break;
	case HSC_ABORT:
		tcp_abort(hsess->tpcb);
		err = ERR_ABRT; /* lwip callback functions need to be notified */
		break;
	default: /* HSC_KILL */
		err = ERR_OK;
		break;
	}

	/* unlink session from session list */
	if (hsess->prev)
		hsess->prev->next = hsess->next;
	else
		hs->hsess_head = hsess->next;
	if (hsess->next)
		hsess->next->prev = hsess->prev;
	else
		hs->hsess_tail = hsess->prev;

	/* release memory */
	mempool_put(hsess->pobj);
	--hs->nb_sess;

	return err;
}

static err_t httpsess_recv(void *argp, struct tcp_pcb *tpcb, struct pbuf *p, err_t err)
{
	/* lwIP pbuf handling depending on return value:
	 *  On ERR_ABRT indicates an aborted session to lwIP
	 *  On !ERR_OK, the pbuf is hold back and repassed later
	 *  On ERR_OK, we have to free the buffer here and inform the
	 *   sender about the received data */
	struct http_sess *hsess = argp;
	struct http_req *cpreq;
	struct pbuf *q;
	unsigned int prev_rqueue_len;
	size_t plen;
	err_t ret = ERR_OK;

	if (unlikely(!p || err != ERR_OK)) {
		/* receive error: kill connection */
		printd("Unexpected session error (p=%p, err=%d)\n", p, err);
		if (p) {
			tcp_recved(tpcb, p->tot_len);
			pbuf_free(p);
		}
		return httpsess_close(hsess, HSC_ABORT);
	}

	if (unlikely(hsess->retry_replychain)) {
		/* We end up here when we were not able to start the reply chain
		 *  The pbuf is reinjected by lwIP (since we returned ERR_MEM previously).
		 *  Hence, we need to ignore it because it has been already
		 *  processed by the parser */
		printd("Try to start reply chain again...\n");
		ret = httpsess_respond(hsess);
		if (ret == ERR_MEM) {
			printd("Replying failed: Out of memory\n");
			goto out; /* still did not work, retry it again later */
		}
		if (ret == ERR_ABRT)
			goto out; /* connection got aborted */
		hsess->retry_replychain = 0;
		goto out;
	}

	cpreq = hsess->cpreq;
	if (unlikely(!cpreq || hsess->state != HSS_ESTABLISHED)) {
		/* We don't have an object allocated for parsing the requests or
		 * we are about to close the connection, thus ignoring all further
		 * incoming data
		 *  This can only happen after the first request was processed
		 *  and there are two reasons for this:
		 *  1) We couldn't allocate such an object previously
		 *  2) User requested connection close
		 *  However, we will ignore all further incoming data
		 *
		 * TODO: Is ignoring a clean way to handle these cases because
		 *       we will send ack on the wire? */
		printd("Ignoring unrelated data (p=%p, len=%d)\n", p, p->tot_len);
		goto out;
	}

	switch (cpreq->state) {
	case HRS_PARSING_HDR:
	case HRS_PARSING_MSG:
		/* feed parser */
		prev_rqueue_len = hsess->rqueue_len;
		httpsess_halt_keepalive(hsess);
		for (q = p; q != NULL; q = q->next) {
			plen = http_parser_execute(&hsess->parser, &_http_parser_settings,
			                           q->payload, q->len);
			if (unlikely(hsess->parser.upgrade)) {
				/* protocol upgrade requested */
				printd("Unsupported HTTP protocol upgrade requested: Dropping connection...\n");
				ret = httpsess_close(hsess, HSC_CLOSE);
				goto out;
			}
			if (unlikely(plen != q->len)) {
				/* less data was parsed: this happens only when
				 * there was a parsing error */
				printd("HTTP protocol parsing error: Dropping connection...\n");
				ret = httpsess_close(hsess, HSC_CLOSE);
				goto out;
			}
		}

		printd("prev_rqueue_len == %u, hsess->rqueue_len = %u\n",
		        prev_rqueue_len, hsess->rqueue_len);
		if (prev_rqueue_len == 0 && hsess->rqueue_len) {
			/* new request came in: start reply chain */
			printd("Starting reply chain...\n");
			ret = httpsess_respond(hsess);
			if (ret == ERR_MEM) {
				/* out of memory for replying.
				 * We will retry it later by holding the current
				 * pbuf back in the stack */
				printd("Replying failed: Out of memory\n");
				hsess->retry_replychain = 1;
				goto out;
			}
			goto out;
		}
		break;
	default:
		/* this case never happens */
		printd("FATAL: Invalid receive state\n");
		break;
	}

 out:
	if (likely(ret != ERR_MEM)) {
		tcp_recved(tpcb, p->tot_len);
		pbuf_free(p);
	}
	return ret;
}

static void httpsess_error(void *argp, err_t err)
{
	struct http_sess *hsess = argp;
	printd("Killing HTTP session %p due to error: %d\n", hsess, err);
	httpsess_close(hsess, HSC_KILL); /* drop connection */
}

/* Is called every 5 sec */
static err_t httpsess_poll(void *argp, struct tcp_pcb *tpcb)
{
	struct http_sess *hsess = argp;

	printd("poll session %p\n", hsess);
	if (unlikely(hsess->keepalive_timer == 0)) {
		/* keepalive timeout: close connection */
		if (hsess->sent_infly == 0) {
			return httpsess_close(hsess, HSC_CLOSE);
		} else {
			/* we need to wait for the client until it ack'ed */
			hsess->state = HSS_CLOSING;
		}
	}
	if (hsess->keepalive_timer > 0)
		--hsess->keepalive_timer;
	return ERR_OK;
}

/**
 * Call tcp_write() in a loop trying smaller and smaller length
 *
 * @param pcb tcp_pcb to send
 * @param ptr Data to send
 * @param length Length of data to send (in/out: on return, contains the
 *        amount of data sent)
 *        Note: length can be at most tcp_sndbuf()
 * @param apiflags directly passed to tcp_write
 * @return the return value of tcp_write
 */
err_t httpsess_write(struct http_sess *hsess, const void* buf, size_t *len, uint8_t apiflags)
{
	struct tcp_pcb *pcb = hsess->tpcb;
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
	hsess->sent_infly += s;
	*len = s;
	return err;
}

static err_t httpsess_sent(void *argp, struct tcp_pcb *tpcb, uint16_t len)
{
	struct http_sess *hsess = argp;

	printd("ACK for session %p\n", hsess);

	hsess->sent_infly -= len;
	switch (hsess->state) {
	case HSS_ESTABLISHED:
		if (len)
			return httpsess_acknowledge(hsess, len); /* will continue replying */
		break;

	case HSS_CLOSING:
		/* connection is about to be closed:
		 * check if all bytes were transmitted
		 * and close it if so */
		if (hsess->sent_infly == 0)
			return httpsess_close(hsess, HSC_CLOSE);
		break;

	default:
		printd("ERROR: session %p in unknown state: %d\n",
		        hsess, hsess->state);
		break;
	}


	return ERR_OK;
}

/*******************************************************************************
 * HTTP request parsing
 ******************************************************************************/
static int httprecv_hdr_url(struct http_parser *parser, const char *buf, size_t len)
{
	struct http_sess *hsess = container_of(parser, struct http_sess, parser);
	struct http_req *hreq = hsess->cpreq;
	register size_t i, curpos, maxlen;

	curpos = hreq->request.url_len;
	maxlen = sizeof(hreq->request.url) - 1 - curpos;
	if (unlikely(len > maxlen)) {
		hreq->request.url_overflow = 1; /* Out of memory */
		len = maxlen;
	}

	if (!hreq->request.url_argp) {
		for (i = 0; i < len; ++i) {
			hreq->request.url[curpos + i] = buf[i];

			if (buf[i] == HTTPURL_ARGS_INDICATOR) {
				hreq->request.url_argp = &hreq->request.url[curpos + i];
				hreq->request.url_len += i;
				len    -= i;
				buf    += i;
				curpos += i;
				goto memcpy;
			}
		}
	} else {
  memcpy:
		MEMCPY(&hreq->request.url[curpos], buf, len);
	}
	hreq->request.url_len += len;
	return 0;
}

static int httprecv_req_complete(struct http_parser *parser)
{
	struct http_sess *hsess = container_of(parser, struct http_sess, parser);
	struct http_req *hreq;

	printd("Parsing finalized: Enqueueing request...\n");
	/* because we finished parsing at this point, we remove the http request object
	 * from the current parsing and enqueue it to the reply queue
	 * We might try to add a object new one later, if this request will reply
	 * keepalive enabled
	 * Note: The parser does not have to be resetted since it continues parsing
	 *       the input */
	hreq = hsess->cpreq;
	hsess->cpreq = NULL;
	if (hsess->rqueue_tail)
		hsess->rqueue_tail->next = hreq;
	else
		hsess->rqueue_head = hreq;
	hsess->rqueue_tail = hreq;
	++hsess->rqueue_len;

	/* Because keepalive is only 0 when parsing is completed or client
	 * requested it, we try here to allocate a new request object if this
	 * was not the last message */
	hsess->keepalive = http_should_keep_alive(&hsess->parser);
	if (hsess->keepalive) {
		hsess->cpreq = httpreq_open(hsess);
		if (!hsess->cpreq) {
			/* Could not allocate next object: close connection */
			printd("Could not allocate a new request object: "
			        "Connection will close after serving is finished\n");
			hsess->keepalive = 0;
		}
	}

	/* copy data */
	hreq->request.keepalive = hsess->keepalive;
	hreq->request.http_major = parser->http_major;
	hreq->request.http_minor = parser->http_minor;
	hreq->request.http_errno = parser->http_errno;
	hreq->request.method = parser->method;

	/* finalize request lines by adding terminating '\0' */
	http_recvhdr_terminate(&hreq->request.hdr);
	hreq->request.url[hreq->request.url_len++] = '\0';
	hreq->state = HRS_PREPARING_HDR;

	return 0;
}

static inline void httpreq_prepare_hdr(struct http_req *hreq)
{
	size_t url_offset = 0;
	size_t nb_slines = 0;
	size_t nb_dlines = 0;
#ifdef HTTP_TESTFILE
	hash512_t h;
#endif
#if defined SHFS_STATS && defined SHFS_STATS_HTTP && defined SHFS_STATS_HTTP_DPC
	register unsigned int i;
#endif
#ifdef HTTP_DEBUG
	unsigned l;
#endif
	char strsbuf[64];
	char strlbuf[128];

	/* check request method (GET, POST, ...) */
	if (hreq->request.method != HTTP_GET) {
		printd("Invalid/unsupported request method: %u HTTP/%hu.%hu\n",
		        hreq->request.method,
		        hreq->request.http_major,
		        hreq->request.http_minor);
		goto err501_hdr; /* 501 Invalid request */
	}

#ifdef HTTP_DEBUG
	printd("GET %s HTTP/%hu.%hu\n",
	        hreq->request.url,
	        hreq->request.http_major,
	        hreq->request.http_minor);
	for (l = 0; l < hreq->request.hdr.nb_lines; ++l) {
		printd("   %s: %s\n",
		       hreq->request.hdr.line[l].field.b,
		       hreq->request.hdr.line[l].value.b);
	}
#endif

	/* try to open requested file and construct header */
	/* eliminate leading '/'s */
	while (hreq->request.url[url_offset] == '/')
		++url_offset;

#ifdef HTTP_URL_CUTARGS
	/* remove args from URL when there was a filename passed (-> "open by filename") */
	if (hreq->request.url_argp &&
	    &(hreq->request.url[url_offset]) != hreq->request.url_argp)
		*(hreq->request.url_argp) = '\0';
#endif

#ifdef HTTP_TESTFILE
	if ((hreq->request.url[url_offset] == HTTPURL_ARGS_INDICATOR) &&
	    (hash_parse(&hreq->request.url[url_offset + 1], h, shfs_vol.hlen) == 0)) {
		if (hash_is_zero(h, shfs_vol.hlen))
			goto testfile_hdr0; /* fixed-size testfile */
		if (hash_is_max(h, shfs_vol.hlen))
			goto testfile_hdr1; /* infinite testfile */
	}
#endif
	hreq->fd = shfs_fio_open(&hreq->request.url[url_offset]);
	if (!hreq->fd) {
		printd("Could not open requested file '%s': %s\n", &hreq->request.url[url_offset], strerror(errno));
		if (errno == ENOENT || errno == ENODEV)
			goto err404_hdr; /* 404 File not found */
		goto err500_hdr; /* 500 Internal server error */
	}
#if defined SHFS_STATS && defined SHFS_STATS_HTTP
	hreq->stats.el_stats = shfs_stats_from_fd(hreq->fd);
#endif
	if (shfs_fio_islink(hreq->fd)) {
		if (shfs_fio_link_type(hreq->fd) == SHFS_LTYPE_REDIRECT)
			goto red307_hdr; /* 307 temporary moved */

		/**
		 * REMOTE LINK HANDLING
		 * Note: header will be built in next phase (HRS_BUILDING_HDR)
		 * Here, upstream connection is established (if non existent)
		 */
		hreq->type = HRT_LINKMSG;
		if (httpreq_link_prepare_hdr(hreq) < 0) {
			shfs_fio_close(hreq->fd);
			hreq->fd = NULL;
			goto err500_hdr;
		}
		return;
	}

	/**
	 * LOCAL FILE HEADER
	 */
	/* call build HDR directly on local file I/O -> skip HRS_BUILDING_HDR phase switch */
	hreq->type = HRT_FIOMSG;
	httpreq_fio_build_hdr(hreq);
#if defined SHFS_STATS && defined SHFS_STATS_HTTP && defined SHFS_STATS_HTTP_DPC
	for (i = 0; i < SHFS_STATS_HTTP_DPCR; ++i)
		hreq->stats.dpc_threshold[i] = SHFS_STATS_HTTP_DPC_THRESHOLD(hreq->f.fsize, i);
#endif
	hreq->state = HRS_FINALIZING_HDR;
	return;

	/**
	 * REDIRECT HEADER
	 */
 red307_hdr:
	hreq->response.code = 307;
	http_sendhdr_add_shdr(&hreq->response.hdr, &nb_slines,
			      HTTP_SHDR_307(hreq->request.http_major, hreq->request.http_minor));
	strshfshost(strsbuf, sizeof(strsbuf),
		    shfs_fio_link_rhost(hreq->fd));
	shfs_fio_link_rpath(hreq->fd, strlbuf, sizeof(strlbuf));
	http_sendhdr_add_dline(&hreq->response.hdr, &nb_dlines,
			       "%shttp://%s:%"PRIu16"/%s\r\n", _http_dhdr[HTTP_DHDR_LOCATION],
			       strsbuf, shfs_fio_link_rport(hreq->fd), strlbuf);
	hreq->type = HRT_NOMSG;
	goto err_out;

	/**
	 * TESTFILE HEADER
	 */
#ifdef HTTP_TESTFILE
 testfile_hdr0: /* testfile with fixed length */
	hreq->response.code = 200;
	http_sendhdr_add_shdr(&hreq->response.hdr, &nb_slines,
			      HTTP_SHDR_200(hreq->request.http_major, hreq->request.http_minor));
	http_sendhdr_add_shdr(&hreq->response.hdr, &nb_slines, HTTP_SHDR_PLAIN);

	/* Content length */
	http_sendhdr_add_dline(&hreq->response.hdr, &nb_dlines,
			       "%s%"PRIu64"\r\n", _http_dhdr[HTTP_DHDR_SIZE],
			       _http_testfile_len);
	hreq->rlen = _http_testfile_len;
	hreq->type = HRT_SMSG;
	hreq->smsg = _http_testfile;
	goto err_out;

 testfile_hdr1: /* infinite testfile */
	hreq->response.code = 200;
	http_sendhdr_add_shdr(&hreq->response.hdr, &nb_slines,
			      HTTP_SHDR_200(hreq->request.http_major, hreq->request.http_minor));
	http_sendhdr_add_shdr(&hreq->response.hdr, &nb_slines, HTTP_SHDR_PLAIN);

	hreq->rlen = sizeof(_http_testfile) - 1;
	hreq->type = HRT_SMSG_INF;
	hreq->smsg = _http_testfile;
	hreq->is_stream = 1;
	goto err_out;
#endif

	/**
	 * ERROR HEADERS
	 */
 err404_hdr:
	/* 404 File not found */
	hreq->response.code = 404;
	http_sendhdr_add_shdr(&hreq->response.hdr, &nb_slines,
			      HTTP_SHDR_404(hreq->request.http_major, hreq->request.http_minor));
	http_sendhdr_add_shdr(&hreq->response.hdr, &nb_slines,HTTP_SHDR_HTML);
	http_sendhdr_add_shdr(&hreq->response.hdr, &nb_slines,HTTP_SHDR_NOCACHE);
	/* Content length */
	http_sendhdr_add_dline(&hreq->response.hdr, &nb_dlines,
			       "%s%"PRIu64"\r\n", _http_dhdr[HTTP_DHDR_SIZE],
			       _http_err404p_len);
	hreq->type = HRT_SMSG;
	hreq->smsg = _http_err404p;
	hreq->rlen = _http_err404p_len;
	goto err_out;

 err500_hdr:
	/* 500 Internal server error */
	hreq->response.code = 500;
	http_sendhdr_add_shdr(&hreq->response.hdr, &nb_slines,
			      HTTP_SHDR_500(hreq->request.http_major, hreq->request.http_minor));
	http_sendhdr_add_shdr(&hreq->response.hdr, &nb_slines, HTTP_SHDR_HTML);
	/* Content length */
	http_sendhdr_add_dline(&hreq->response.hdr, &nb_dlines,
			       "%s%"PRIu64"\r\n", _http_dhdr[HTTP_DHDR_SIZE],
			       _http_err500p_len);
	hreq->type = HRT_SMSG;
	hreq->smsg = _http_err500p;
	hreq->rlen = _http_err500p_len;
	goto err_out;

 err501_hdr:
	/* 501 Invalid request */
	hreq->response.code = 501;
	http_sendhdr_add_shdr(&hreq->response.hdr, &nb_slines,
			      HTTP_SHDR_501(hreq->request.http_major, hreq->request.http_minor));
	http_sendhdr_add_shdr(&hreq->response.hdr, &nb_slines, HTTP_SHDR_HTML);
	/* Content length */
	http_sendhdr_add_dline(&hreq->response.hdr, &nb_dlines,
			       "%s%"PRIu64"\r\n", _http_dhdr[HTTP_DHDR_SIZE],
			       _http_err501p_len);
	hreq->type = HRT_SMSG;
	hreq->smsg = _http_err501p;
	hreq->rlen = _http_err501p_len;
	goto err_out;

 err_out:
	http_sendhdr_set_nbslines(&hreq->response.hdr, nb_slines);
	http_sendhdr_set_nbdlines(&hreq->response.hdr, nb_dlines);
	hreq->state = HRS_FINALIZING_HDR;
	return;
}

static inline void httpreq_build_hdr(struct http_req *hreq)
{
	size_t nb_slines = 0;
	size_t nb_dlines = 0;
	int ret;

	/* For now, just remote links utilize this phase for connecting to 
	 * upstream server. All other reponses are already build
	 * Because of this it might be possible that this function needs
	 * to be called multiple times until the connection was established */
	ASSERT(shfs_fio_islink(hreq->fd));
	ASSERT(shfs_fio_link_type(hreq->fd) != SHFS_LTYPE_REDIRECT);

	ret = httpreq_link_build_hdr(hreq);
	if (ret == -EAGAIN)
		return; /* stay in current phase because we are not done yet */
	if (ret < 0) {
		httpreq_link_close(hreq);
		shfs_fio_close(hreq->fd);
		goto err503_hdr; /* an unknown error happend -> send out a 503 error page instead */
	}

	/* we are done -> switch to next phase */
	hreq->state = HRS_FINALIZING_HDR;
	return;

 err503_hdr:
	/* 503 Service unavailable */
	hreq->response.code = 503;
	http_sendhdr_add_shdr(&hreq->response.hdr, &nb_slines,
			      HTTP_SHDR_503(hreq->request.http_major, hreq->request.http_minor));
	http_sendhdr_add_shdr(&hreq->response.hdr, &nb_slines, HTTP_SHDR_HTML);
	/* Content length */
	http_sendhdr_add_dline(&hreq->response.hdr, &nb_dlines,
			       "%s%"PRIu64"\r\n", _http_dhdr[HTTP_DHDR_SIZE],
			       _http_err503p_len);
	/* Retry-after (TODO: replace the hard-coded 2 second) */
	http_sendhdr_add_dline(&hreq->response.hdr, &nb_dlines,
			       "%s%u\r\n", _http_dhdr[HTTP_DHDR_RETRY],
			       2);
	hreq->type = HRT_SMSG;
	hreq->smsg = _http_err503p;
	hreq->rlen = _http_err503p_len;
	http_sendhdr_set_nbslines(&hreq->response.hdr, nb_slines);
	http_sendhdr_set_nbdlines(&hreq->response.hdr, nb_dlines);
	hreq->state = HRS_FINALIZING_HDR;
	return;
}

static inline void httpreq_finalize_hdr(struct http_req *hreq)
{
	size_t nb_slines = http_sendhdr_get_nbslines(&hreq->response.hdr);
	size_t nb_dlines = http_sendhdr_get_nbdlines(&hreq->response.hdr);
#ifdef HTTP_DEBUG
	register unsigned l;
#endif

	/* Default header lines */
	http_sendhdr_add_shdr(&hreq->response.hdr, &nb_slines, HTTP_SHDR_SERVER);
	http_sendhdr_add_shdr(&hreq->response.hdr, &nb_slines, HTTP_SHDR_ACC_BYTERANGE);

	/* keepalive */
	if (!hreq->request.keepalive || hreq->is_stream)
		http_sendhdr_add_shdr(&hreq->response.hdr, &nb_slines, HTTP_SHDR_CONN_CLOSE);
	else
		http_sendhdr_add_shdr(&hreq->response.hdr, &nb_slines, HTTP_SHDR_CONN_KEEPALIVE);

	/* Calculate final header length */
	http_sendhdr_set_nbslines(&hreq->response.hdr, nb_slines);
	http_sendhdr_set_nbdlines(&hreq->response.hdr, nb_dlines);
	hreq->response.hdr_total_len = http_sendhdr_calc_totallen(&hreq->response.hdr);

#ifdef HTTP_DEBUG
	printd("Response:\n");
	for (l = 0; l < hreq->response.hdr.nb_slines; ++l) {
		printd("   %s",
		       hreq->response.hdr.sline[l].b);
	}
	for (l = 0; l < hreq->response.hdr.nb_dlines; ++l) {
		printd("   %s",
		       hreq->response.hdr.dline[l].b);
	}
	printd(" Header length: %lu\n", hreq->response.hdr.total_len);
	printd(" Body length:   %lu\n", hreq->rlen + _http_sep_len);
#endif
#ifdef HTTP_DEBUG_PRINTACCESS
	printk("[%03u] %s\n",
	       hreq->response_hdr.code,
	       hreq->request.url);
#endif
}

static inline err_t httpsess_write_sbuf(struct http_sess *hsess, size_t *sent,
                                        const char *sbuf, size_t sbuf_len)
{
	register size_t apos = *sent;   /* absolute offset in hdr */
	register const void *ptr;
	size_t slen;             /* left bytes of sbuffer */
	err_t err;

	slen = (sbuf_len - apos);
	ptr = sbuf + apos;
	err = httpsess_write(hsess, ptr, &slen, TCP_WRITE_FLAG_MORE);
	*sent += slen;
	return err;
}

static inline err_t httpsess_write_sbuf_inf(struct http_sess *hsess, size_t *sent,
					    const char *sbuf, size_t sbuf_len)
{
	register size_t apos;
	register const void *ptr;
	size_t slen;
	err_t err;

	do {
		apos = (*sent) % sbuf_len;
		slen = (sbuf_len - apos);

		ptr = sbuf + apos;
		err = httpsess_write(hsess, ptr, &slen, TCP_WRITE_FLAG_MORE);
		*sent += slen;
	} while(err == ERR_OK && slen);
	return err;
}

#define httpreq_len(hreq) \
	((hreq)->response.hdr_total_len + (hreq)->rlen)

#define httpreq_acked(hreq) \
	((hreq)->response.hdr_acked_len + (hreq)->alen + (hreq)->response.ftr_acked_len)

#define httpreq_infly(hreq) \
	((hreq)->is_stream ? 1 : httpreq_len((hreq)) - httpreq_acked((hreq)))

static inline void httpreq_finalize(struct http_req *hreq)
{
	struct http_sess *hsess = hreq->hsess;

	if (httpreq_infly(hreq)) {
		/* append reqest to aqueue */
		printd("request %p appended to aqueue because not all data was acknowledged yet\n", hreq);
		hreq->next = NULL;
		if (hsess->aqueue_tail)
			hsess->aqueue_tail->next = hreq;
		else
			hsess->aqueue_head = hreq;
		hsess->aqueue_tail = hreq;
	} else {
		httpreq_close(hreq);
	}
}

/* Resume reply with next enqueued reply.
 * If there is no reply in queue, close the http session or
 * wait for next request by client if keepalive is enabled */
static inline err_t httpsess_eor(struct http_sess *hsess)
{
	struct http_req *hreq = hsess->rqueue_head;

	httpsess_flush(hsess);
	if (hreq->next) {
		/* resume reply with next request from queue */
		printd("continue with next request %p\n", hreq->next);
		hsess->rqueue_head = hreq->next;
		--hsess->rqueue_len;
		httpreq_finalize(hreq);
		return httpsess_respond(hsess);
	} else {
		/* close connection/wait because of keepalive */
		hsess->rqueue_head = NULL;
		hsess->rqueue_tail = NULL;
		hsess->rqueue_len = 0;
		httpreq_finalize(hreq);

		if (hsess->keepalive) {
			printd("start keep-alive timeout\n");
			/* wait for next request */
			httpsess_reset_keepalive(hsess);
			return ERR_OK;
		} else {
			/* close connection */
			printd("close session\n");
			hsess->state = HSS_CLOSING;
		}
	}

	return ERR_OK;
}

/* Send out http response
 * Note: Will be called multiple times while a request is handled */
err_t httpsess_respond(struct http_sess *hsess)
{
	struct http_req *hreq;
	err_t err = ERR_OK;

	BUG_ON(hsess->state != HSS_ESTABLISHED);
	BUG_ON(hsess->_in_respond >= 1); /* no function nesting: FIXME: Happens still in some cases -> backtrace */
	BUG_ON(!hsess->rqueue_head);

	hsess->_in_respond = 1;
	hreq = hsess->rqueue_head;
	switch (hreq->state) {
	case HRS_PREPARING_HDR: /* atomic -> direct state transition */
		httpreq_prepare_hdr(hreq);
		if (hreq->state == HRS_FINALIZING_HDR) {
			/* skipping next phase requested */
			goto case_FINALIZING_HDR;
		}
		goto case_BUILDING_HDR;

	case_BUILDING_HDR:
		hreq->state = HRS_BUILDING_HDR;
	case HRS_BUILDING_HDR:
		httpreq_build_hdr(hreq); /* might need to be re-called */
		if (hreq->state == HRS_FINALIZING_HDR) {
			/* we are done -> switch to next phase */
			goto case_FINALIZING_HDR;
		}
		break;

	case_FINALIZING_HDR: /* atomic -> direct state transition */
		hreq->state = HRS_FINALIZING_HDR;
	case HRS_FINALIZING_HDR:
		httpreq_finalize_hdr(hreq);
		goto case_HRS_RESPONDING_HDR;

	case_HRS_RESPONDING_HDR:
		hreq->state = HRS_RESPONDING_HDR;
		hsess->sent = 0;
	case HRS_RESPONDING_HDR:
		/* send out header */
		//err = httpreq_write_hdr(hreq, &hsess->sent);
		err = http_sendhdr_write(&hreq->response.hdr, &hsess->sent,
					 (tcpwrite_fn_t) httpsess_write, (void *) hsess);
		if (unlikely(err))
			goto err_close;

		if (hsess->sent == hreq->response.hdr_total_len) {
			/* we are done -> switch to next phase */
			if (hreq->type == HRT_NOMSG)
				goto case_HRS_RESPONDING_EOM;
			goto case_HRS_RESPONDING_MSG;
		}
		break;

	case_HRS_RESPONDING_MSG:
		hreq->state = HRS_RESPONDING_MSG;
		hsess->sent = 0;
	case HRS_RESPONDING_MSG:
		switch(hreq->type) {
		case HRT_SMSG:
			err = httpsess_write_sbuf(hsess, &hsess->sent, hreq->smsg, hreq->rlen);
			if (unlikely(err))
				goto err_close;

			if (hsess->sent == hreq->rlen)
				goto case_HRS_RESPONDING_EOM; /* we are done */
			break;

#ifdef HTTP_TESTFILE
		case HRT_SMSG_INF:
			err = httpsess_write_sbuf_inf(hsess, &hsess->sent, hreq->smsg, hreq->rlen);
			if (unlikely(err))
				goto err_close;
			/* we will never be done ;-) */
			break;
#endif

		case HRT_FIOMSG:
			/* send out data from file */
			err = httpreq_write_fio(hreq, &hsess->sent);
			if (unlikely(err != ERR_OK && err != ERR_MEM))
				goto err_close; /* drop connection because of an unrecoverable error */

#if defined SHFS_STATS && defined SHFS_STATS_HTTP && defined SHFS_STATS_HTTP_DPC
			while (unlikely(hsess->sent >= hreq->stats.dpc_threshold[hreq->stats.dpc_i]))
				++hreq->stats.el_stats->p[hreq->stats.dpc_i++];
#endif

			if (unlikely(hsess->sent == hreq->rlen)) {
				/* we are done */
#if defined SHFS_STATS && defined SHFS_STATS_HTTP
				++hreq->stats.el_stats->c; /* successfully completed request */
#endif
				goto case_HRS_RESPONDING_EOM;
			}
			break;

		case HRT_LINKMSG:
		default:
			goto err_close;
		}
		break;

	case_HRS_RESPONDING_EOM:
		hreq->state = HRS_RESPONDING_EOM;
		hsess->sent = 0;
	case HRS_RESPONDING_EOM:
		err = httpsess_write_sbuf(hsess, &hsess->sent,
		                          _http_sep, _http_sep_len);
		if (hsess->sent == _http_sep_len) {
			/* we are done */
			err = httpsess_eor(hsess);
			if (unlikely(err))
				goto err_close;
		}
		break;

	default:
		/* unknown state?! */
		printd("FATAL: HTTP request in invalid state\n");
		BUG_ON(1);
		goto err_close;
	}
	hsess->_in_respond = 0;
	return ERR_OK;

 err_close:
	hsess->_in_respond = 0;
	/* error happened -> kill connection */
	return httpsess_close(hsess, HSC_ABORT);
}

static inline void httpreq_acknowledge(struct http_req *hreq, size_t *len, int *isdone)
{
	size_t acked = *len;
	size_t hdr_infly;
	uint64_t msg_infly;
	size_t ftr_infly;

	hdr_infly = hreq->response.hdr_total_len - hreq->response.hdr_acked_len;
	if (hdr_infly) {
		printd("hdr_infly: %"PRIu64"\n", (uint64_t) hdr_infly);
		if (hdr_infly > acked) {
			hreq->response.hdr_acked_len += acked;
			acked = 0;
		} else {
			hreq->response.hdr_acked_len += hdr_infly;
			acked -= hdr_infly;
		}
	}

	if (hreq->is_stream) {
		hreq->alen += acked;
		//if (acked && hreq->type == HRT_LINKMSG)
		//	httpreq_ack_link(hreq, acked);
		*len = 0;
		*isdone = 0;
		return;
	}

	msg_infly = hreq->rlen - hreq->alen;
	if (msg_infly) {
		printd("msg_infly: %"PRIu64"\n", (uint64_t) msg_infly);
		if (msg_infly > acked) {
			hreq->alen += acked;
			if (acked && hreq->type == HRT_FIOMSG)
				httpreq_ack_fio(hreq, acked);
			acked = 0;
		} else {
			hreq->alen += msg_infly;
			acked -= msg_infly;
			if (msg_infly && hreq->type == HRT_FIOMSG)
				httpreq_ack_fio(hreq, msg_infly);
		}
	}

	/* adds 2 bytes to keep-alive connections */
	if (hreq->hsess->keepalive) {
	ftr_infly = _http_sep_len - hreq->response.ftr_acked_len;
	printd("ftr_infly: %"PRIu64"\n", (uint64_t) ftr_infly);
	if (ftr_infly > acked) {
		hreq->response.ftr_acked_len += acked;
		*len = 0;
		*isdone = 0;
		return;
	}
	hreq->response.ftr_acked_len += ftr_infly;
	acked -= ftr_infly;
	}
	*len = acked;
	*isdone = 1;
}

static err_t httpsess_acknowledge(struct http_sess *hsess, size_t len)
{
	struct http_req *hreq;
	int isdone = 0;

	printd("Client acknowledged %"PRIu64" bytes\n", (uint64_t) len);
	while (len) {
		hreq = hsess->aqueue_head;
		if (hreq) {
			printd("Acknowledge on request %p (len: %"PRIu64", acked: %"PRIu64" -> %"PRIu64", left: %"PRIu64" -> %"PRIu64")\n",
			        hreq, httpreq_len(hreq),
			        httpreq_acked(hreq),
			        httpreq_infly(hreq) < len ? httpreq_len(hreq) : httpreq_acked(hreq) + len,
			        httpreq_infly(hreq),
			        httpreq_infly(hreq) < len ? 0 : httpreq_infly(hreq) - len);
			httpreq_acknowledge(hreq, &len, &isdone);
			if (isdone) {
				printd("Serving of request %p is done\n", hreq);
				/* dequeue and close request that is done */
				if (hreq->next) {
					hsess->aqueue_head = hreq->next;
				} else {
					hsess->aqueue_head = NULL;
					hsess->aqueue_tail = NULL;
				}
				httpreq_close(hreq);
			}
			continue;
		}

		/* no request is left on aqueue, pick current request */
		hreq = hsess->rqueue_head;
		BUG_ON(!hreq); /* Client acknowledged data that was
		                  not sent out yet?! (or simply the object got closed already) */

		printd("Acknowledge on current request %p (len: %"PRIu64", acked: %"PRIu64" -> %"PRIu64", left: %"PRIu64" -> %"PRIu64")\n",
		        hreq, (uint64_t) httpreq_len(hreq),
		        httpreq_acked(hreq),
		        httpreq_infly(hreq) < len ? httpreq_len(hreq) : httpreq_acked(hreq) + len,
		        httpreq_infly(hreq),
		        httpreq_infly(hreq) < len ? 0 : httpreq_infly(hreq) - len);
		httpreq_acknowledge(hreq, &len, &isdone);
		BUG_ON(len > 0);
	}

	if (hsess->rqueue_head)
		return httpsess_respond(hsess);
	return ERR_OK;
}

#ifdef HTTP_INFO
static int shcmd_http_info(FILE *cio, int argc, char *argv[])
{
	uint16_t nb_sess, max_nb_sess;
	uint32_t nb_reqs, max_nb_reqs;
	uint16_t nb_links, max_nb_links;
	unsigned long pver;
	size_t fio_nb_buffers = 0;
	size_t link_nb_buffers = 0;
	size_t fio_bffrlen = 0;
	size_t link_bffrlen = 0;

	if (!hs) {
		fprintf(cio, "HTTP server is not online\n");
		return -1;
	}

	/* copy values in order to print them
	 * (writing to cio can lead to thread switching) */
	nb_sess      = hs->nb_sess;
	max_nb_sess  = hs->max_nb_sess;
	nb_reqs      = hs->nb_reqs;
	max_nb_reqs  = hs->max_nb_reqs;
	nb_links     = hs->nb_links;
	max_nb_links = hs->max_nb_links;
	pver         = http_parser_version();
	if (shfs_mounted) {
		fio_nb_buffers = httpreq_fio_nb_buffers(shfs_vol.chunksize);
		fio_bffrlen = shfs_vol.chunksize * fio_nb_buffers;
		link_nb_buffers = httpreq_link_nb_buffers(shfs_vol.chunksize);
		link_bffrlen = shfs_vol.chunksize * link_nb_buffers;
	}

	/* thread switching might happen from here on */
	fprintf(cio, " Listen port:                           %8"PRIu16"\n", HTTP_LISTEN_PORT);
	fprintf(cio, " Number of sessions:                   %4"PRIu16"/%4"PRIu16"\n", nb_sess,  max_nb_sess);
	fprintf(cio, " Number of requests:                   %4"PRIu32"/%4"PRIu32"\n", nb_reqs,  max_nb_reqs);
	fprintf(cio, " Number of active uplinks:             %4"PRIu16"/%4"PRIu16"\n", nb_links, max_nb_links);
	if (fio_nb_buffers) {
		fprintf(cio, " File-I/O chunkbuffer chain length:     %8"PRIu64, (uint64_t) fio_nb_buffers);
		fprintf(cio, " (%"PRIu64" KiB)\n", (uint64_t) fio_bffrlen / 1024);
		fprintf(cio, " Remote link chunkbuffer chain length:  %8"PRIu64, (uint64_t) link_nb_buffers);
		fprintf(cio, " (%"PRIu64" KiB)\n", (uint64_t) link_bffrlen / 1024);
	}
	fprintf(cio, " Maximum TCP send buffer:               %8"PRIu64" KiB", (uint64_t) HTTPREQ_TCP_MAXSNDBUF / 1024);
	fprintf(cio, "\n");
	fprintf(cio, " HTTP parser version:                     %2hu.%hu.%hu\n",
	        (pver >> 16) & 255, /* major */
	        (pver >> 8) & 255, /* minor */
	        (pver) & 255); /* patch */
	return 0;
}
#endif
