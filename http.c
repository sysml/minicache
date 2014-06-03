/*
 * HTTP - A tiny high performance HTTP server for Mini-OS
 *  This HTTP server is based on http_parser (from nginx)
 *  The filesystem backend SHFS is directly bound to it
 *
 * Copyright(C) 2014 NEC Laboratories Europe. All rights reserved.
 *                   Simon Kuenzer <simon.kuenzer@neclab.eu>
 */
#include <mini-os/os.h>
#include <mini-os/types.h>
#include <mini-os/xmalloc.h>
#include <lwip/tcp.h>
#include <mempool.h>
#include "shfs.h"
#include "shfs_fio.h"
#if defined SHFS_STATS && defined SHFS_STATS_HTTP
#include "shfs_stats.h"
#endif

#include "http_parser.h"
#include "http_data.h"
#include "http.h"

#ifdef HTTP_DEBUG
#define ENABLE_DEBUG
#endif
#include "debug.h"

#define HTTP_POLL_INTERVAL        10 /* = x * 500ms; 10 = 5s */
#define HTTP_KEEPALIVE_TIMEOUT     3 /* = x * HTTP_POLL_INTERVAL */
#define HTTP_TCPKEEPALIVE_TIMEOUT 90 /* = x sec */
#define HTTP_TCPKEEPALIVE_IDLE    30 /* = x sec */

#define HTTPHDR_URL_MAXLEN        67 /* '/' + ':' + 512 bits hash + '\0' */
#define HTTPHDR_BUFFER_MAXLEN     64
#define HTTPHDR_REQ_MAXNB_LINES   16
#define HTTPHDR_RESP_MAXNB_SLINES  8
#define HTTPHDR_RESP_MAXNB_DLINES  8

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
#ifndef min4
#define min4(a, b, c, d) \
	min(min((a), (b)), min((c), (d)))
#endif

#ifndef container_of
/**
 * container_of - cast a member of a structure out to the containing structure
 * @ptr:        the pointer to the member.
 * @type:       the type of the container struct this is embedded in.
 * @member:     the name of the member within the struct.
 *
 */
#define container_of(ptr, type, member) ({                      \
        const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
        (type *)( (char *)__mptr - offsetof(type,member) );})
#endif

enum http_sess_close {
	HSC_CLOSE = 0, /* call tcp_close to close the connection */
	HSC_ABORT, /* call tcp_abort */
	HSC_KILL /* do not touch the tcp_pcb any more */
};

struct http_srv {
	struct tcp_pcb *tpcb;
	struct mempool *sess_pool;
	struct mempool *req_pool;
	struct http_parser_settings parser_settings;

	uint16_t nb_sess;
	uint16_t max_nb_sess;
	uint32_t nb_reqs;
	uint32_t max_nb_reqs;
};

struct _hdr_dbuffer {
	char b[HTTPHDR_BUFFER_MAXLEN];
	size_t len;
};

struct _hdr_sbuffer {
	const char *b;
	size_t len;
};

struct _hdr_line {
	struct _hdr_dbuffer field;
	struct _hdr_dbuffer value;
};

enum http_sess_state {
	HSS_UNDEF = 0,
	HSS_ESTABLISHED,
	HSS_CLOSING
};

struct http_sess {
	struct mempool_obj *pobj;
	struct http_srv *hsrv;
	struct tcp_pcb *tpcb;
	enum http_sess_state state;
	size_t sent_infly;
	size_t sent;

	struct http_parser parser;
	struct http_parser_settings *parser_settings;

	int keepalive;
	int keepalive_timer; /* -1 timeout disabled, 0 timeout expired */

	struct http_req *cpreq; /* current request that is parsed */
	struct http_req *rqueue_head; /* request serve queue of parsed requests */
	struct http_req *rqueue_tail;
	unsigned int rqueue_len; /* current number of simultaneous requests */

	int retry_replychain; /* marker for rare cases: reply could not be initiated
	                       * within recv because of ERR_MEM */
};

enum http_req_state {
	HRS_UNDEF = 0,
	HRS_PARSING_HDR,
	HRS_PARSING_MSG,
	HRS_MAKING_RESP,
	HRS_RESPONDING_HDR,
	HRS_RESPONDING_MSG,
	HRS_RESPONDING_EMSG,
	HRS_RESPONDING_EOM
};

struct http_req {
	struct mempool_obj *pobj;
	struct http_sess *hsess;
	struct http_req *next;
	enum http_req_state state;

	struct {
		uint8_t http_major;
		uint8_t http_minor;
		uint8_t http_errno;
		uint8_t method;
		int keepalive;
		char url[HTTPHDR_URL_MAXLEN];
		size_t url_len;
		int url_overflow;
		struct _hdr_line line[HTTPHDR_REQ_MAXNB_LINES];
		uint32_t nb_lines;
		int last_was_value;
		int lines_overflow; /* more lines in request header than memory available */
	} request_hdr;

	struct {
		unsigned int code;
		struct _hdr_sbuffer sline[HTTPHDR_RESP_MAXNB_SLINES];
		struct _hdr_dbuffer dline[HTTPHDR_RESP_MAXNB_DLINES];
		uint32_t nb_slines;
		size_t slines_tlen;
		uint32_t nb_dlines;
		size_t dlines_tlen;
		size_t eoh_off; /* end of header offset */
		size_t total_len; /* total length (inclusive EOH line) */
	} response_hdr;

	SHFS_FD fd;
	uint64_t fsize; /* file size */
	uint64_t rfirst; /* (requested) first byte to read from file */
	uint64_t rlast;  /* (requested) last byte to read from file */
	uint64_t rlen; /* (requested) number of bytes to read */
	chk_t volchk_first;
	chk_t volchk_last;
	uint32_t volchkoff_first;
	uint32_t volchkoff_last;

	struct mempool_obj *chk_buf[2]; /* references to chunk buffers for I/O */
	chk_t chk_buf_addr[2];
	SHFS_AIO_TOKEN *chk_buf_aiotoken[2];
	int chk_buf_aioret[2];
	unsigned int chk_buf_idx;

#if defined SHFS_STATS && defined SHFS_STATS_HTTP
	struct {
		struct shfs_el_stats *el_stats;
#ifdef SHFS_STATS_HTTP_DPC
		unsigned int dpc_i;
		uint64_t dpc_threshold[SHFS_STATS_HTTP_DPCR];
#endif
	} stats;
#endif
};

#if !(HTTP_MULTISERVER)
static struct http_srv *hs = NULL;
#endif

static err_t httpsess_accept (void *argp, struct tcp_pcb *new_tpcb, err_t err);
static err_t httpsess_close  (struct http_sess *hsess, enum http_sess_close type);
static err_t httpsess_sent   (void *argp, struct tcp_pcb *tpcb, uint16_t len);
static err_t httpsess_recv   (void *argp, struct tcp_pcb *tpcb, struct pbuf *p, err_t err);
static void  httpsess_error  (void *argp, err_t err);
static err_t httpsess_poll   (void *argp, struct tcp_pcb *tpcb);
static err_t httpsess_respond(struct http_sess *hsess);
static int httprecv_req_complete(struct http_parser *parser);
static int httprecv_hdr_url(struct http_parser *parser, const char *buf, size_t len);
static int httprecv_hdr_field(struct http_parser *parser, const char *buf, size_t len);
static int httprecv_hdr_value(struct http_parser *parser, const char *buf, size_t len);

#if HTTP_MULTISERVER
struct http_srv *init_http(uint16_t nb_sess, uint32_t nb_reqs, uint16_t port)
#else
int init_http(uint16_t nb_sess, uint32_t nb_reqs)
#endif
{
	err_t err;
	int ret = 0;

	hs = _xmalloc(sizeof(*hs), PAGE_SIZE);
	if (!hs) {
#if HTTP_MULTISERVER
		errno = ENOMEM;
#else
		ret = -ENOMEM;
#endif
		goto err_out;
	}
	hs->max_nb_sess = nb_sess;
	hs->nb_sess = 0;
	hs->max_nb_reqs = nb_reqs;
	hs->nb_reqs = 0;

	/* allocate session pool */
	hs->sess_pool = alloc_simple_mempool(hs->max_nb_sess, sizeof(struct http_sess));
	if (!hs->sess_pool) {
#if HTTP_MULTISERVER
		errno = ENOMEM;
#else
		ret = -ENOMEM;
#endif
		goto err_free_hs;
	}

	/* allocate request pool */
	hs->req_pool = alloc_simple_mempool(hs->max_nb_reqs, sizeof(struct http_req));
	if (!hs->req_pool) {
#if HTTP_MULTISERVER
		errno = ENOMEM;
#else
		ret = -ENOMEM;
#endif
		goto err_free_sesspool;
	}

	/* register TCP listener */
	hs->tpcb = tcp_new();
	if (!hs->tpcb) {
#if HTTP_MULTISERVER
		errno = ENOMEM;
#else
		ret = -ENOMEM;
#endif
		goto err_free_reqpool;
	}
#if HTTP_MULTISERVER
	err = tcp_bind(hs->tpcb, IP_ADDR_ANY, port);
#else
	err = tcp_bind(hs->tpcb, IP_ADDR_ANY, HTTP_LISTEN_PORT);
#endif
	if (err != ERR_OK) {
#if HTTP_MULTISERVER
		errno = err;
#else
		ret = -err;
#endif
		goto err_free_tcp;
	}
	hs->tpcb = tcp_listen(hs->tpcb);
	tcp_arg(hs->tpcb, hs);
	tcp_accept(hs->tpcb, httpsess_accept); /* register session accept */

	/* parser settings */
	hs->parser_settings.on_message_begin = NULL;
	hs->parser_settings.on_url = httprecv_hdr_url;
	hs->parser_settings.on_status = NULL;
	hs->parser_settings.on_header_field = httprecv_hdr_field;
	hs->parser_settings.on_header_value = httprecv_hdr_value;
	hs->parser_settings.on_headers_complete = NULL;
	hs->parser_settings.on_body = NULL;
	hs->parser_settings.on_message_complete = httprecv_req_complete;

	dprintf("HTTP server %p initialized\n", hs);

	return ret;

 err_free_tcp:
	tcp_abort(hs->tpcb);
 err_free_reqpool:
	free_mempool(hs->req_pool);
 err_free_sesspool:
	free_mempool(hs->sess_pool);
 err_free_hs:
	xfree(hs);
 err_out:
#if HTTP_MULTISERVER
	return NULL;
#else
	return ret;
#endif
}

#if HTTP_MULTISERVER
void exit_http(struct http_srv *hs)
#else
void exit_http(void)
#endif
{
	tcp_close(hs->tpcb);
	free_mempool(hs->sess_pool);
	xfree(hs);
#if !(HTTP_MULTISERVER)
	hs = NULL;
#endif
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

#define httpsess_reset_parser(hsess)	  \
	do { \
		http_parser_init(&(hsess)->parser, HTTP_REQUEST);	\
		httpsess_reset_keepalive((hsess));	  \
	} while(0)

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
	hreq->request_hdr.nb_lines = 0;
	hreq->request_hdr.url_len = 0;
	hreq->request_hdr.url_overflow = 0;
	hreq->request_hdr.last_was_value = 1;
	hreq->request_hdr.lines_overflow = 0;
	hreq->fd = NULL;
	hreq->chk_buf_idx = UINT_MAX;
	hreq->chk_buf[0] = NULL;
	hreq->chk_buf[1] = NULL;
	hreq->chk_buf_addr[0] = 0;
	hreq->chk_buf_addr[1] = 0;
#if defined SHFS_STATS && defined SHFS_STATS_HTTP && defined SHFS_STATS_HTTP_DPC
	hreq->stats.dpc_i = 0;
#endif

	++hsess->hsrv->nb_reqs;
	return hreq;
}

static inline void httpreq_close(struct http_req *hreq)
{
	struct http_sess *hsess = hreq->hsess;

	/* wait for I/O exit and close open file */
	if (hreq->fd) {
		hreq->chk_buf_idx = UINT_MAX; /* disable calling of httpsess_response from aio cb */

		dprintf("Wait for unfinished I/O...\n");
		shfs_aio_wait(hreq->chk_buf_aiotoken[0]);
		shfs_aio_wait(hreq->chk_buf_aiotoken[1]);
		dprintf("Done\n");
	}

	if (hreq->chk_buf[1])
		mempool_put(hreq->chk_buf[1]);
	if (hreq->chk_buf[0])
		mempool_put(hreq->chk_buf[0]);

	if (hreq->fd) {
		shfs_fio_close(hreq->fd);
	}

	mempool_put(hreq->pobj);
	--hsess->hsrv->nb_reqs;
}

static err_t httpsess_accept(void *argp, struct tcp_pcb *new_tpcb, err_t err)
{
	struct mempool_obj *hsobj;
	struct http_sess *hsess;
#if HTTP_MULTISERVER
	struct http_srv *hs = argp;
#endif

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
	hsess->retry_replychain = 0;

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
	hsess->parser.data = hsess;
	hsess->parser_settings = &hs->parser_settings;
	httpsess_reset_parser(hsess);

	hsess->state = HSS_ESTABLISHED;
	++hs->nb_sess;
	dprintf("New HTTP session accepted on server %p "
		"(currently, there are %u/%u open sessions)\n",
		hs, hs->nb_sess, hs->max_nb_sess);
	return 0;

 err_free_hsess:
	mempool_put(hsobj);
 err_out:
	dprintf("Session establishment declined on server %p "
		"(currently, there are %u/%u open sessions)\n",
		hs, hs->nb_sess, hs->max_nb_sess);
	return err;
}

static err_t httpsess_close(struct http_sess *hsess, enum http_sess_close type)
{
#if HTTP_MULTISERVER
	struct http_srv *hs = hsess->hs;
#endif
	struct http_req *hreq;
	err_t err;

	ASSERT(hsess != NULL);

	/* disable tcp connection */
	tcp_arg(hsess->tpcb,  NULL);
	tcp_sent(hsess->tpcb, NULL);
	tcp_recv(hsess->tpcb, NULL);
	tcp_sent(hsess->tpcb, NULL);
	tcp_err(hsess->tpcb,  NULL);
	tcp_poll(hsess->tpcb, NULL, 0);

	/* close unserved requests */
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

	/* release memory */
	mempool_put(hsess->pobj);
	--hs->nb_sess;

	dprintf("HTTP session %s (caller: 0x%x)\n", (type == HSC_ABORT ? "aborted" :
	                                             (type == HSC_CLOSE ? "closed" : "killed")), get_caller());
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
		dprintf("Unexpected session error (p=%p, err=%d)\n", p, err);
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
		dprintf("Try to start reply chain again...\n");
		ret = httpsess_respond(hsess);
		if (ret == ERR_MEM) {
			dprintf("Replying failed: Out of memory\n");
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
		dprintf("Ignoring unrelated data (p=%p, len=%d)\n", p, p->tot_len);
		goto out;
	}

	switch (cpreq->state) {
	case HRS_PARSING_HDR:
	case HRS_PARSING_MSG:
		/* feed parser */
		prev_rqueue_len = hsess->rqueue_len;
		httpsess_halt_keepalive(hsess);
		for (q = p; q != NULL; q = q->next) {
			plen = http_parser_execute(&hsess->parser, hsess->parser_settings,
			                           q->payload, q->len);
			if (unlikely(hsess->parser.upgrade)) {
				/* protocol upgrade requested */
				dprintf("Unsupported HTTP protocol upgrade requested: Dropping connection...\n");
				ret = httpsess_close(hsess, HSC_CLOSE);
				goto out;
			}
			if (unlikely(plen != q->len)) {
				/* less data was parsed: this happens only when
				 * there was a parsing error */
				dprintf("HTTP protocol parsing error: Dropping connection...\n");
				ret = httpsess_close(hsess, HSC_CLOSE);
				goto out;
			}
		}

		dprintf("prev_rqueue_len == %u, hsess->rqueue_len = %u\n",
		        prev_rqueue_len, hsess->rqueue_len);
		if (prev_rqueue_len == 0 && hsess->rqueue_len) {
			/* new request came in: start reply chain */
			dprintf("Starting reply chain...\n");
			ret = httpsess_respond(hsess);
			if (ret == ERR_MEM) {
				/* out of memory for replying.
				 * We will retry it later by holding the current
				 * pbuf back in the stack */
				dprintf("Replying failed: Out of memory\n");
				hsess->retry_replychain = 1;
				goto out;
			}
			goto out;
		}
		break;
	default:
		/* this case never happens */
		dprintf("FATAL: Invalid receive state\n");
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
	dprintf("Killing HTTP session due to error: %d\n", err);
	httpsess_close(hsess, HSC_KILL); /* drop connection */
}

/* Is called every 5 sec */
static err_t httpsess_poll(void *argp, struct tcp_pcb *tpcb)
{
	struct http_sess *hsess = argp;

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
 * @param apiflags directly passed to tcp_write
 * @return the return value of tcp_write
 */
static err_t httpsess_write(struct http_sess *hsess, const void* buf, uint16_t *len, uint8_t apiflags)
{
	struct tcp_pcb *pcb = hsess->tpcb;
	uint16_t l;
	err_t err;

	l = *len;
	if (l == 0)
		return ERR_OK;

	do {
		err = tcp_write(pcb, buf, l, apiflags);
		if (unlikely(err == ERR_MEM)) {
			if ((tcp_sndbuf(pcb) == 0) ||
			    (tcp_sndqueuelen(pcb) >= TCP_SND_QUEUELEN))
				/* no need to try smaller sizes */
				l = 1;
			else
				l /= 2;
		}
	} while ((err == ERR_MEM) && (l > 1));

	hsess->sent_infly += l;
	*len = l;

	return err;
}

#define httpsess_flush(hsess) tcp_output((hsess)->tpcb)

static err_t httpsess_sent(void *argp, struct tcp_pcb *tpcb, uint16_t len) {
	struct http_sess *hsess = argp;
	struct http_req *hreq;

	hsess->sent_infly -= len;
	switch (hsess->state) {
	case HSS_ESTABLISHED:
		hreq = hsess->rqueue_head;
		if (likely(hreq != NULL)) {
			switch (hreq->state) {
			case HRS_RESPONDING_HDR:
			case HRS_RESPONDING_MSG:
			case HRS_RESPONDING_EMSG:
				/* continue replying */
				if (len) {
					dprintf("Client acknowledged %u bytes, continue...\n", len);
					return httpsess_respond(hsess);
				}
				break;
			default:
				break;
			}
		}
		break;

	case HSS_CLOSING:
		/* connection is about to be closed:
		 * check if all bytes were transmitted
		 * and close it if so */
		if (hsess->sent_infly == 0)
			return httpsess_close(hsess, HSC_CLOSE);

	default:
		break;
	}


	return ERR_OK;
}

/*******************************************************************************
 * HTTP request parsing
 ******************************************************************************/
static void _hdr_dbuffer_add(struct _hdr_dbuffer *dst, const char *src, size_t len)
{
	register size_t curpos, maxlen;

	curpos = dst->len;
	maxlen = sizeof(dst->b) - 1 - curpos; /* minus 1 to store terminating '\0' later */

	len = min(maxlen, len);
	MEMCPY(&dst->b[curpos], src, len);
	dst->len += len;
}

static void _hdr_dbuffer_terminate(struct _hdr_dbuffer *dst)
{
	dst->b[dst->len++] = '\0';
}

static int httprecv_hdr_url(struct http_parser *parser, const char *buf, size_t len)
{
	struct http_sess *hsess = container_of(parser, struct http_sess, parser);
	struct http_req *hreq = hsess->cpreq;
	register size_t curpos, maxlen;

	curpos = hreq->request_hdr.url_len;
	maxlen = sizeof(hreq->request_hdr.url) - 1 - curpos;
	if (unlikely(len > maxlen)) {
		hreq->request_hdr.url_overflow = 1; /* Out of memory */
		len = maxlen;
	}
	MEMCPY(&hreq->request_hdr.url[curpos], buf, len);
	hreq->request_hdr.url_len += len;
	return 0;
}

static int httprecv_hdr_field(struct http_parser *parser, const char *buf, size_t len)
{
	struct http_sess *hsess = container_of(parser, struct http_sess, parser);
	struct http_req *hreq = hsess->cpreq;
	register unsigned l;

	if (unlikely(hreq->request_hdr.lines_overflow))
		return 0; /* ignore line */
	if (unlikely(hreq->request_hdr.last_was_value)) {
		if (unlikely(hreq->request_hdr.nb_lines == HTTPHDR_REQ_MAXNB_LINES)) {
			/* overflow */
			hreq->request_hdr.lines_overflow = 1;
			return 0;
		}

		/* switch to next line and reset its buffer */
		hreq->request_hdr.last_was_value = 0;
		hreq->request_hdr.line[hreq->request_hdr.nb_lines].field.len = 0;
		hreq->request_hdr.line[hreq->request_hdr.nb_lines].value.len = 0;
		++hreq->request_hdr.nb_lines;
	}

	l = hreq->request_hdr.nb_lines - 1;
	_hdr_dbuffer_add(&hreq->request_hdr.line[l].field, buf, len);
	return 0;
}

static int httprecv_hdr_value(struct http_parser *parser, const char *buf, size_t len)
{
	struct http_sess *hsess = container_of(parser, struct http_sess, parser);
	struct http_req *hreq = hsess->cpreq;
	register unsigned l;

	if (unlikely(hreq->request_hdr.lines_overflow))
		return 0; /* ignore line */
	if (unlikely(!hreq->request_hdr.last_was_value))
		hreq->request_hdr.last_was_value = 1; /* value parsing began */
	if (unlikely(hreq->request_hdr.nb_lines == 0))
		return -EINVAL; /* parsing error */

	l = hreq->request_hdr.nb_lines - 1;
	_hdr_dbuffer_add(&hreq->request_hdr.line[l].value, buf, len);
	return 0;
}

/* returns the field line number on success, -1 if it was not found */
static inline int http_reqhdr_findfield(struct http_req *hreq, const char *field)
{
	register unsigned l;

	for (l = 0; l < hreq->request_hdr.nb_lines; ++l) {
		if (strncasecmp(field, hreq->request_hdr.line[l].field.b,
		                hreq->request_hdr.line[l].field.len) == 0) {
			return (int) l;
		}
	}

	return -1; /* not found */
}

/*******************************************************************************
 * HTTP Request handling
 ******************************************************************************/
#define ADD_RESHDR_SLINE(hreq, i, shdr_code)	  \
	do { \
		(hreq)->response_hdr.sline[(i)].b = _http_shdr[(shdr_code)]; \
		(hreq)->response_hdr.sline[(i)].len = _http_shdr_len[(shdr_code)]; \
		++(i); \
	} while(0)

#define ADD_RESHDR_DLINE(hreq, i, fmt, ...)	  \
	do { \
		(hreq)->response_hdr.dline[(i)].len = \
			snprintf((hreq)->response_hdr.dline[(i)].b, \
			         HTTPHDR_BUFFER_MAXLEN, \
			         (fmt), \
			         ##__VA_ARGS__); \
		++(i); \
	} while(0)

static int httprecv_req_complete(struct http_parser *parser)
{
	struct http_sess *hsess = container_of(parser, struct http_sess, parser);
	struct http_req *hreq;
	register uint32_t l;

	dprintf("Parsing finalized: Enqueueing request...\n");
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
			dprintf("Could not allocate a new request object: "
			        "Connection will close after serving is finished\n");
			hsess->keepalive = 0;
		}
	}

	/* copy data */
	hreq->request_hdr.keepalive = hsess->keepalive;
	hreq->request_hdr.http_major = parser->http_major;
	hreq->request_hdr.http_minor = parser->http_minor;
	hreq->request_hdr.http_errno = parser->http_errno;
	hreq->request_hdr.method = parser->method;

	/* finalize request_hdr lines by adding terminating '\0' */
	for (l = 0; l < hreq->request_hdr.nb_lines; ++l) {
		_hdr_dbuffer_terminate(&hreq->request_hdr.line[l].field);
		_hdr_dbuffer_terminate(&hreq->request_hdr.line[l].value);
	}
	hreq->request_hdr.url[hreq->request_hdr.url_len++] = '\0';
	hreq->state = HRS_MAKING_RESP;

	return 0;
}

static inline void httpreq_make_response(struct http_req *hreq)
{
	register size_t url_offset = 0;
	register int ret;
	register size_t nb_slines = 0;
	register size_t nb_dlines = 0;
	register uint32_t l;
#if defined SHFS_STATS && defined SHFS_STATS_HTTP && defined SHFS_STATS_HTTP_DPC
	register unsigned int i;
#endif
	char fmime[65]; /* mime type of element */

	/* check request method (GET, POST, ...) */
	if (hreq->request_hdr.method != HTTP_GET) {
		dprintf("Invalid/unsupported request method: %u HTTP/%u.%u\n",
		        hreq->request_hdr.method,
		        hreq->request_hdr.http_major,
		        hreq->request_hdr.http_minor);
		goto err501_hdr; /* 501 Invalid request */
	}

#ifdef HTTP_DEBUG
	dprintf("GET %s HTTP/%u.%u\n",
	        hreq->request_hdr.url,
	        hreq->request_hdr.http_major,
	        hreq->request_hdr.http_minor);
	for (l = 0; l < hreq->request_hdr.nb_lines; ++l) {
		dprintf("   %s: %s\n",
		       hreq->request_hdr.line[l].field.b,
		       hreq->request_hdr.line[l].value.b);
	}
#endif

	/* try to open requested file and construct header */
	/* eliminate leading '/'s */
	while (hreq->request_hdr.url[url_offset] == '/')
		++url_offset;
	hreq->fd = shfs_fio_open(&hreq->request_hdr.url[url_offset]);
	if (!hreq->fd) {
		dprintf("Could not open requested file '%s': %s\n", &hreq->request_hdr.url[url_offset], strerror(errno));
		if (errno == ENOENT || errno == ENODEV)
			goto err404_hdr; /* 404 File not found */
		goto err500_hdr; /* 500 Internal server error */
	}

	/* pick and reserve exclusively chunk buffers for async I/O */
	hreq->chk_buf[0] = mempool_pick(shfs_vol.chunkpool);
	if (!hreq->chk_buf[0]) {
		dprintf("Could not get a chunk buffer from SHFS\n");
		goto err503_hdr; /* 503 Service temporarily unavailable (we ran out of memory) */
	}
	hreq->chk_buf[1] = mempool_pick(shfs_vol.chunkpool);
	if (!hreq->chk_buf[1]) {
		dprintf("Could not get a chunk buffer from SHFS\n");
		goto err503_hdr; /* 503 Service temporarily unavailable (we ran out of memory) */
	}

	hreq->response_hdr.code = 200;	/* 200 OK */
	shfs_fio_size(hreq->fd, &hreq->fsize);
#if defined SHFS_STATS && defined SHFS_STATS_HTTP
	hreq->stats.el_stats = shfs_stats_from_fd(hreq->fd);
#if defined SHFS_STATS_HTTP_DPC
	for (i = 0; i < SHFS_STATS_HTTP_DPCR; ++i)
		hreq->stats.dpc_threshold[i] = SHFS_STATS_HTTP_DPC_THRESHOLD(hreq->fsize, i);
#endif
#endif

	/* File range requested? */
	hreq->rfirst = 0;
	hreq->rlast  = hreq->fsize - 1;
	ret = http_reqhdr_findfield(hreq, "range");
	if (ret >= 0) {
		/* Because range requests require different answer codes
		 * (e.g., 206 OK or 416 EINVAL), we need to check the
		 * range request here already.
		 * http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.16 */
		hreq->response_hdr.code = 416;
		if (strncasecmp("bytes=", hreq->request_hdr.line[ret].value.b, 6) == 0) {
			uint64_t rfirst;
			uint64_t rlast;

			ret = sscanf(hreq->request_hdr.line[ret].value.b + 6,
			             "%lu-%lu",
			             &rfirst, &rlast);
			if (ret == 1) {
				/* only rfirst specified */
				if (rfirst < hreq->rlast) {
					hreq->rfirst = rfirst;
					hreq->response_hdr.code = 206;
				}
			} else if (ret == 2) {
				/* both, rfirst and rlast, specified */
				if ((rfirst < rlast) &&
				    (rfirst < hreq->rlast) &&
				    (rlast <= hreq->rlast)) {
					hreq->rfirst = rfirst;
					hreq->rlast = rlast;
					hreq->response_hdr.code = 206;
				}
			}
		}

		if (hreq->response_hdr.code == 416) {
			/* (parsing/out of range) error: response with 416 error header */
			dprintf("Could not parse range request\n");
			ADD_RESHDR_SLINE(hreq, nb_slines, HTTP_SHDR_416(hreq->request_hdr.http_major, hreq->request_hdr.http_minor));
			ADD_RESHDR_DLINE(hreq, nb_dlines, "%s%lu\r\n", _http_dhdr[HTTP_DHDR_SIZE], 0);
			goto finalize_hdr;
		}

		dprintf("Client requested range of element: %lu-%lu\n",
		        hreq->rfirst, hreq->rlast);
	}

	/* HTTP OK [first line] (code can be 216 or 200) */
	if (hreq->response_hdr.code == 206)
		ADD_RESHDR_SLINE(hreq, nb_slines, HTTP_SHDR_206(hreq->request_hdr.http_major, hreq->request_hdr.http_minor));

	else
		ADD_RESHDR_SLINE(hreq, nb_slines, HTTP_SHDR_OK(hreq->request_hdr.http_major, hreq->request_hdr.http_minor));

	/* MIME (by element or default) */
	shfs_fio_mime(hreq->fd, fmime, sizeof(fmime));
	if (fmime[0] == '\0')
		ADD_RESHDR_SLINE(hreq, nb_slines, HTTP_SHDR_DEFAULT_TYPE);
	else
		ADD_RESHDR_DLINE(hreq, nb_dlines, "%s%s\r\n", _http_dhdr[HTTP_DHDR_MIME], fmime);

	/* Content length */
	hreq->rlen   = (hreq->rlast + 1) - hreq->rfirst;
	ADD_RESHDR_DLINE(hreq, nb_dlines, "%s%lu\r\n", _http_dhdr[HTTP_DHDR_SIZE], hreq->rlen);

	/* Content range */
	if (hreq->response_hdr.code == 206)
		ADD_RESHDR_DLINE(hreq, nb_dlines, "%s%lu-%lu/%lu\r\n",
		                 _http_dhdr[HTTP_DHDR_RANGE],
		                 hreq->rfirst, hreq->rlast, hreq->fsize);

	/* Initialize volchk range values for I/O */
	if (hreq->rlen != 0) {
		hreq->volchk_first = shfs_volchk_foff(hreq->fd, hreq->rfirst);                      /* first volume chunk of file */
		hreq->volchk_last  = shfs_volchk_foff(hreq->fd, hreq->rlast + hreq->rfirst);       /* last volume chunk of file */
		hreq->volchkoff_first = shfs_volchkoff_foff(hreq->fd, hreq->rfirst);                /* first byte in first chunk */
		hreq->volchkoff_last  = shfs_volchkoff_foff(hreq->fd, hreq->rlast + hreq->rfirst); /* last byte in last chunk */
	}

 finalize_hdr:
	/* Default header lines */
	ADD_RESHDR_SLINE(hreq, nb_slines, HTTP_SHDR_SERVER);
	ADD_RESHDR_SLINE(hreq, nb_slines, HTTP_SHDR_ACC_BYTERANGE);

	/* keepalive */
	if (hreq->request_hdr.keepalive) {
		ADD_RESHDR_SLINE(hreq, nb_slines, HTTP_SHDR_CONN_KEEPALIVE);
	} else {
		ADD_RESHDR_SLINE(hreq, nb_slines, HTTP_SHDR_CONN_CLOSE);
	}

	/* Calculate final header length */
	hreq->response_hdr.slines_tlen = 0;
	for (l = 0; l < nb_slines; ++l)
		hreq->response_hdr.slines_tlen += hreq->response_hdr.sline[l].len;
	hreq->response_hdr.dlines_tlen = 0;
	for (l = 0; l < nb_dlines; ++l)
		hreq->response_hdr.dlines_tlen += hreq->response_hdr.dline[l].len;
	hreq->response_hdr.eoh_off   = hreq->response_hdr.slines_tlen + hreq->response_hdr.dlines_tlen;
	hreq->response_hdr.total_len = hreq->response_hdr.eoh_off + _http_shdr_len[HTTP_EOH];
	hreq->response_hdr.nb_slines = nb_slines;
	hreq->response_hdr.nb_dlines = nb_dlines;

	/* Switch this request object to reply phase */
	hreq->state = HRS_RESPONDING_HDR;

#ifdef HTTP_DEBUG
	dprintf("Response:\n");
	for (l = 0; l < hreq->response_hdr.nb_slines; ++l) {
		dprintf("   %s",
		       hreq->response_hdr.sline[l].b);
	}
	for (l = 0; l < hreq->response_hdr.nb_dlines; ++l) {
		dprintf("   %s",
		       hreq->response_hdr.dline[l].b);
	}
#endif
	return;

	/**
	 * ERROR HEADERS
	 */
 err404_hdr:
	/* 404 File not found */
	hreq->response_hdr.code = 404;
	ADD_RESHDR_SLINE(hreq, nb_slines, HTTP_SHDR_404(hreq->request_hdr.http_major, hreq->request_hdr.http_minor));
	ADD_RESHDR_SLINE(hreq, nb_slines, HTTP_SHDR_HTML);
	ADD_RESHDR_SLINE(hreq, nb_slines, HTTP_SHDR_NOCACHE);
	/* Content length */
	ADD_RESHDR_DLINE(hreq, nb_dlines, "%s%lu\r\n", _http_dhdr[HTTP_DHDR_SIZE], _http_err404p_len);
	goto finalize_hdr;

 err500_hdr:
	/* 500 Internal server error */
	hreq->response_hdr.code = 500;
	ADD_RESHDR_SLINE(hreq, nb_slines, HTTP_SHDR_500(hreq->request_hdr.http_major, hreq->request_hdr.http_minor));
	ADD_RESHDR_SLINE(hreq, nb_slines, HTTP_SHDR_HTML);
	ADD_RESHDR_SLINE(hreq, nb_slines, HTTP_SHDR_NOCACHE);
	/* Content length */
	ADD_RESHDR_DLINE(hreq, nb_dlines, "%s%lu\r\n", _http_dhdr[HTTP_DHDR_SIZE], _http_err500p_len);
	goto finalize_hdr;

 err501_hdr:
	/* 501 Invalid request */
	hreq->response_hdr.code = 501;
	ADD_RESHDR_SLINE(hreq, nb_slines, HTTP_SHDR_501(hreq->request_hdr.http_major, hreq->request_hdr.http_minor));
	ADD_RESHDR_SLINE(hreq, nb_slines, HTTP_SHDR_HTML);
	ADD_RESHDR_SLINE(hreq, nb_slines, HTTP_SHDR_NOCACHE);
	/* Content length */
	ADD_RESHDR_DLINE(hreq, nb_dlines, "%s%lu\r\n", _http_dhdr[HTTP_DHDR_SIZE], _http_err501p_len);
	goto finalize_hdr;

 err503_hdr:
	/* 503 Service unavailable */
	hreq->response_hdr.code = 503;
	ADD_RESHDR_SLINE(hreq, nb_slines, HTTP_SHDR_503(hreq->request_hdr.http_major, hreq->request_hdr.http_minor));
	ADD_RESHDR_SLINE(hreq, nb_slines, HTTP_SHDR_HTML);
	ADD_RESHDR_SLINE(hreq, nb_slines, HTTP_SHDR_NOCACHE);
	/* Content length */
	ADD_RESHDR_DLINE(hreq, nb_dlines, "%s%lu\r\n", _http_dhdr[HTTP_DHDR_SIZE], _http_err503p_len);
	/* Retry-after (TODO: here, just set to 2 second) */
	ADD_RESHDR_DLINE(hreq, nb_dlines, "%s%lu\r\n", _http_dhdr[HTTP_DHDR_RETRY], 2);
	goto finalize_hdr;

}


/* might be called multiple times until hdr was sent out */
static inline err_t httpreq_write_hdr(struct http_req *hreq, size_t *sent)
{
	struct http_sess *hsess = hreq->hsess;
	register size_t apos = *sent;     /* absolute offset in hdr */
	register size_t aoff_cl, aoff_nl; /* current/next line buffer absolut offset in hdr */
	register size_t l_off;            /* offset in current hdr line */
	register size_t l_left;           /* left of current hdr line */
	register void *ptr;
	register uint32_t l;
	register uint16_t avail;
	uint16_t slen;
	err_t err = ERR_OK;

	avail = tcp_sndbuf(hsess->tpcb);
	if (unlikely(avail == 0))
		return ERR_OK; /* we need to wait for space on tcp sndbuf */
	do {
		if (apos < hreq->response_hdr.slines_tlen) {
			/* static header */
			aoff_nl = 0;
			for (l = 0; l < hreq->response_hdr.nb_slines; ++l) {
				aoff_cl  = aoff_nl;
				aoff_nl += hreq->response_hdr.sline[l].len;
				if ((aoff_cl <= apos) && (apos < aoff_nl)) {
					l_off  = apos - aoff_cl;
					l_left = hreq->response_hdr.sline[l].len - l_off;
					slen = min3(l_left, UINT16_MAX, avail);
					ptr  = (uint8_t *) hreq->response_hdr.sline[l].b + l_off;

					err     = httpsess_write(hsess, ptr, &slen, TCP_WRITE_FLAG_MORE);
					apos   += slen;
					avail  -= slen;
					l_left -= slen;
					if ((avail == 0) || (err != ERR_OK) || (l_left))
						goto out;
				}
			}
		}
		if ((apos >= hreq->response_hdr.slines_tlen) &&
		    (apos <  hreq->response_hdr.eoh_off)) {
			/* dynamic header */
			aoff_nl = hreq->response_hdr.slines_tlen;
			for (l = 0; l < hreq->response_hdr.nb_dlines; ++l) {
				aoff_cl  = aoff_nl;
				aoff_nl += hreq->response_hdr.dline[l].len;
				if ((aoff_cl <= apos) && (apos < aoff_nl)) {
					l_off  = apos - aoff_cl;
					l_left = hreq->response_hdr.dline[l].len - l_off;
					slen = min3(l_left, UINT16_MAX, avail);
					ptr  = (uint8_t *) hreq->response_hdr.dline[l].b + l_off;

					err     = httpsess_write(hsess, ptr, &slen, TCP_WRITE_FLAG_MORE);
					apos   += slen;
					avail  -= slen;
					l_left -= slen;
					if ((avail == 0) || (err != ERR_OK) || (l_left))
						goto out;
				}
			}
		}
		if (apos >= hreq->response_hdr.eoh_off) {
			/* end of header */
			l_off  = apos - hreq->response_hdr.eoh_off;
			l_left = _http_shdr_len[HTTP_EOH] - l_off;
			slen = min(avail, (uint16_t) l_left);
			ptr  = (uint8_t *) _http_shdr[HTTP_EOH] + l_off;

			err     = httpsess_write(hsess, ptr, &slen, TCP_WRITE_FLAG_MORE);
			apos   += slen;
			goto out;
		}
	} while (avail);

 out:
	*sent = apos;
	return err;
}

static inline err_t httpsess_write_sbuf(struct http_sess *hsess, size_t *sent,
                                        const char *sbuf, size_t sbuf_len)
{
	register size_t apos = *sent;     /* absolute offset in hdr */
	register const void *ptr;
	register size_t left;             /* left bytes of sbuffer */
	register uint16_t avail;
	uint16_t slen;
	err_t err;

	avail = tcp_sndbuf(hsess->tpcb);
	if (unlikely(avail == 0))
		return ERR_OK; /* we need to wait for space on tcp sndbuf */
	left = (sbuf_len - apos);
	slen = min3(left, UINT16_MAX, avail);
	ptr = sbuf + apos;
	err = httpsess_write(hsess, ptr, &slen, TCP_WRITE_FLAG_MORE);

	*sent += slen;
	return err;
}

/* async SHFS I/O */
static void _httpreq_shfs_aiocb(SHFS_AIO_TOKEN *t, void *cookie, void *argp)
{
	struct http_req *hreq = (struct http_req *) cookie;
	register unsigned int idx = (unsigned int)(uintptr_t) argp;

	hreq->chk_buf_aioret[idx] = shfs_aio_finalize(t);
	hreq->chk_buf_aiotoken[idx] = NULL;

	/* continue sending process */
	if (idx == hreq->chk_buf_idx) {
		dprintf("** [idx=%u] request done, calling httpsess_respond()\n", idx);
		httpsess_respond(hreq->hsess);
	} else {
		dprintf("** [idx=%u] request done\n", idx);
                /* The TCP stack might be still waiting for more input
                 * of the previous chunk, but this guy seems not to be get
                 * called anymore: enforce it here */
                httpsess_flush(hreq->hsess);
	}
}

static inline int _httpreq_shfs_aioreq(struct http_req *hreq, unsigned int idx)
{
	hreq->chk_buf_aiotoken[idx] = shfs_aread_chunk(hreq->chk_buf_addr[idx], 1,
	                                               hreq->chk_buf[idx]->data,
	                                               _httpreq_shfs_aiocb,
	                                               hreq,
	                                               (void *)(uintptr_t) idx);
	if (unlikely(!hreq->chk_buf_aiotoken[idx])) {
		dprintf("failed setting up request for [idx=%u]!\n", idx);
		return -errno;
	}
	dprintf("request set up for [idx=%u]\n", idx);
	return 0;
}

static inline err_t httpreq_write_shfsafio(struct http_req *hreq, size_t *sent)
{
	register size_t roff, foff;
	register uint16_t avail;
	register uint16_t left;
	register chk_t  cur_chk;
	register size_t chk_off;
	register chk_t next_chk;
	register unsigned int idx;
	register unsigned int next_idx;
	uint16_t slen;
	err_t err;
	int ret;

	idx = hreq->chk_buf_idx;
	roff = *sent; /* offset in request */
	foff = roff + hreq->rfirst;  /* offset in file */
	cur_chk = shfs_volchk_foff(hreq->fd, foff);
 next:
	err = ERR_OK;

	if (idx == UINT_MAX || cur_chk != hreq->chk_buf_addr[idx]) {
		/* we got called for the first time
		 * or requested chunk is not loaded yet (for whatever reason) */
		if (idx == UINT_MAX)
			idx = 0;
		hreq->chk_buf_addr[idx] = cur_chk;
		ret = _httpreq_shfs_aioreq(hreq, idx);
		if (unlikely(ret < 0)) {
			/* !!! TODO: setup a retry when errno happend !!! */
			if (ret == -ENOMEM) {
				dprintf("[idx=%u] could not setup request (out of request objects)...\n", idx);
			}
			err = ERR_MEM; /* could not setup request at all: abort */
			dprintf("[idx=%u] aborting...\n", idx);
			goto err_abort;
		}
		goto out;
	}

	if (hreq->chk_buf_aiotoken[idx] != NULL) {
		/* current request is not done yet,
		 * we need to wait. httpsess_response
		 * will be recalled from within callback */
		dprintf("[idx=%u] current request is not done yet\n", idx);
		goto out;
	}

	/* time for doing a read ahead? */
	next_chk = cur_chk + 1;
	next_idx = (idx + 1) & 0x01; /* (idx + 1) % 2 */
	if (hreq->chk_buf_addr[next_idx] != next_chk &&
	    next_chk <= hreq->volchk_last) {
		/* try to do the read ahaed
		 * on errors, there will by a retry set up */
		hreq->chk_buf_addr[next_idx] = next_chk;
		ret = _httpreq_shfs_aioreq(hreq, next_idx);
		if (unlikely(ret < 0))
			hreq->chk_buf_addr[next_idx] = 0; /* trigger retry */
	}

	/* send out data from chk buffer that is loaded already */
	avail = tcp_sndbuf(hreq->hsess->tpcb);
	if (unlikely(avail == 0)) {
		/* we need to wait for free space on tcp sndbuf
		 * httpsess_response is recalled when client has
		 * acknowledged its received data */
		dprintf("[idx=%u] tcp send buffer is full\n", idx);
		goto out;
	}
	chk_off = shfs_volchkoff_foff(hreq->fd, foff);
	left = min(shfs_vol.chunksize - chk_off, hreq->rlen - roff);
	slen = min3(UINT16_MAX, avail, left);
	err = httpsess_write(hreq->hsess, ((uint8_t *) (hreq->chk_buf[idx]->data)) + chk_off,
	                     &slen, TCP_WRITE_FLAG_MORE | TCP_WRITE_FLAG_COPY);
	                    /* TODO: We need to copy because the buffers might be 
	                     *  obsolete already but client has not yet acknowledged the
	                     *  data yet */
	*sent += slen;
	if (unlikely(err != ERR_OK)) {
		dprintf("[idx=%u] sending failed, aborting this round\n", idx);
		goto out;
	}
	dprintf("[idx=%u] sent %u bytes (%lu-%lu, chunksize: %lu, left on this chunk: %lu)\n",
	        idx, slen, chk_off, chk_off + slen, shfs_vol.chunksize, left - slen);

	/* are we done with this chunkbuffer?
	 *  -> switch to next buffer for next data */
	if (slen == left) {
		dprintf("[idx=%u] switch to next buffer [idx=%u]\n", idx, next_idx);
		idx = next_idx;

		/* It might be the case here that the read ahead operation has
		 * already finished at this point. Thus, no callback would be
		 * called that resumes the transmission. That's why we need to
		 * check for this case here */
		roff += slen; /* new offset */
		foff += slen;
		avail -= slen;
		cur_chk = shfs_volchk_foff(hreq->fd, foff);
		if (hreq->chk_buf_aiotoken[idx] == NULL &&
		    hreq->chk_buf_addr[idx] == cur_chk) {
			hreq->chk_buf_idx = idx;
			dprintf("httpsess_write_shfsafio: next chunk [idx=%u] is ready already, " \
			        "resume processing\n", idx);
			goto next;
		} else {
			dprintf("httpsess_write_shfsafio: next chunk [idx=%u] not ready yet\n", idx);
		}
	}
 out:
	hreq->chk_buf_idx = idx;
	return err;

 err_abort:
	return err;
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
		hsess->rqueue_head = hreq->next;
		--hsess->rqueue_len;
		httpreq_close(hreq);
		return httpsess_respond(hsess);
	} else {
		/* close connection/wait because of keepalive */
		hsess->rqueue_head = NULL;
		hsess->rqueue_tail = NULL;
		hsess->rqueue_len = 0;
		httpreq_close(hreq);

		if (hsess->keepalive) {
			/* wait for next request */
			httpsess_reset_keepalive(hsess);
			return ERR_OK;
		} else {
			/* close connection */
			hsess->state = HSS_CLOSING;
		}
	}

	return ERR_OK;
}

/* Send out http response
 * Note: Will be called multiple times while a request is handled */
static err_t httpsess_respond(struct http_sess *hsess)
{
	struct http_req *hreq;
	size_t len;
	err_t err = ERR_OK;

	BUG_ON(hsess->state != HSS_ESTABLISHED);
	//if (unlikely(hsess->state != HSS_ESTABLISHED))
	//	return ERR_OK;

	hreq = hsess->rqueue_head;
	switch (hreq->state) {
	case HRS_MAKING_RESP:
		httpreq_make_response(hreq);
		hsess->sent = 0;
		goto case_HRS_RESPONDING_HDR;

	case_HRS_RESPONDING_HDR:
	case HRS_RESPONDING_HDR:
		/* send out header */
		err = httpreq_write_hdr(hreq, &hsess->sent);
		if (unlikely(err))
			goto err_close;

		if (hsess->sent == hreq->response_hdr.total_len) {
			/* we are done */
			if (hreq->response_hdr.code >= 200 &&
			    hreq->response_hdr.code < 300) {
				/* response body (file) */
				hreq->state = HRS_RESPONDING_MSG;
				hsess->sent = 0;
				goto case_HRS_RESPONDING_MSG;
			} else if (hreq->response_hdr.code == 404 ||
			           hreq->response_hdr.code == 500 ||
			           hreq->response_hdr.code == 501 ||
			           hreq->response_hdr.code == 503) {
				/* error body */
				hreq->state = HRS_RESPONDING_EMSG;
				hsess->sent = 0;
				goto case_HRS_RESPONDING_EMSG;
			} else {
				/* no body */
				hreq->state = HRS_RESPONDING_EOM;
				hsess->sent = 0;
				goto case_HRS_RESPONDING_EOM;
			}
		}
		break;

	case_HRS_RESPONDING_EMSG:
	case HRS_RESPONDING_EMSG:
		/* send out error message */
		switch (hreq->response_hdr.code) {
		case 404:
			/* Element not found */
			len = _http_err404p_len;
			err = httpsess_write_sbuf(hsess, &hsess->sent, _http_err404p, len);
			break;
		case 501:
			/* Invalid request */
			len = _http_err501p_len;
			err = httpsess_write_sbuf(hsess, &hsess->sent, _http_err501p, len);
			break;
		case 503:
			/* Service unavailable */
			len = _http_err503p_len;
			err = httpsess_write_sbuf(hsess, &hsess->sent, _http_err503p, len);
			break;
		case 500:
		default:
			/* Internal server error */
			len = _http_err500p_len;
			err = httpsess_write_sbuf(hsess, &hsess->sent, _http_err500p, len);
			break;
		}
		if (unlikely(err))
			goto err_close;

		if (hsess->sent == len) {
			/* we are done */
			hreq->state = HRS_RESPONDING_EOM;
			hsess->sent = 0;
			goto case_HRS_RESPONDING_EOM;
		}
		break;

	case_HRS_RESPONDING_MSG:
	case HRS_RESPONDING_MSG:
		/* send out data */
		err = httpreq_write_shfsafio(hreq, &hsess->sent);
		if (unlikely(err))
			goto err_close;

#if defined SHFS_STATS && defined SHFS_STATS_HTTP && defined SHFS_STATS_HTTP_DPC
		while (unlikely(hsess->sent >= hreq->stats.dpc_threshold[hreq->stats.dpc_i]))
			++hreq->stats.el_stats->p[hreq->stats.dpc_i++];
#endif

		if (unlikely(hsess->sent == hreq->rlen)) {
			/* we are done */
#if defined SHFS_STATS && defined SHFS_STATS_HTTP
			++hreq->stats.el_stats->c; /* successfully completed request */
#endif
			hreq->state = HRS_RESPONDING_EOM;
			hsess->sent = 0;
			goto case_HRS_RESPONDING_EOM;
		}
		break;

	case_HRS_RESPONDING_EOM:
	case HRS_RESPONDING_EOM:
		len = _http_shdr_len[HTTP_EOM];
		err = httpsess_write_sbuf(hsess, &hsess->sent, _http_shdr[HTTP_EOM], len);
		if (hsess->sent == len) {
			/* we are done */
			err = httpsess_eor(hsess);
			if (unlikely(err))
				goto err_close;
		}
		break;

	default:
		/* unknown state?! */
		dprintf("FATAL: Invalid send state\n");
		goto err_close;
	}
	return ERR_OK;

 err_close:
	/* error happened -> kill connection */
	return httpsess_close(hsess, HSC_ABORT);
}
