/*
 * HTTP - A tiny high performance HTTP server for Mini-OS
 *  This HTTP server is based on http_parser (from nginx)
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

enum http_sess_state {
	HSS_UNDEF = 0,
	HSS_PARSING_HDR,
	HSS_PARSING_MSG,
	HSS_RESPONDING_HDR,
	HSS_RESPONDING_MSG,
	HSS_RESPONDING_EMSG,
	HSS_CLOSING
};

enum http_sess_close {
	HSC_CLOSE = 0, /* call tcp_close to close the connection */
	HSC_ABORT, /* call tcp_abort */
	HSC_KILL /* do not touch the tcp_pcb any more */
};

struct http_srv {
	struct tcp_pcb *tpcb;
	struct mempool *sess_pool;
	struct http_parser_settings parser_settings;

	uint32_t nb_sess;
	uint32_t max_nb_sess;
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

struct http_sess {
	struct mempool_obj *pobj;
	struct http_srv *hsrv;
	struct tcp_pcb *tpcb;
	size_t sent_infly;

	enum http_sess_state state;
	struct http_parser parser;
	struct http_parser_settings *parser_settings;

	struct {
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

	size_t sent;
	int keepalive;
	int keepalive_timer; /* -1 timeout disabled, 0 timeout expired */

	SHFS_FD fd;
	char fmime[65]; /* mime type of file */
	char fname[65]; /* name of file */
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
struct http_srv *init_http(int nb_sess, uint16_t port)
#else
int init_http(int nb_sess)
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

	/* register TCP listener */
	hs->tpcb = tcp_new();
	if (!hs->tpcb) {
#if HTTP_MULTISERVER
		errno = ENOMEM;
#else
		ret = -ENOMEM;
#endif
		goto err_free_sesspool;
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

	return ret;

 err_free_tcp:
	tcp_abort(hs->tpcb);
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
 * Session handling
 ******************************************************************************/
#define httpsess_reset_keepalive(hsess) \
	do { \
		(hsess)->keepalive_timer = HTTP_KEEPALIVE_TIMEOUT; \
	} while(0)
#define httpsess_disable_keepalive(hsess) \
	do { \
		(hsess)->keepalive_timer = -1; \
	} while(0)

static inline void httpsess_reset(struct http_sess *hsess)
{
	/* close open file */
	if (hsess->fd)
		shfs_fio_close(hsess->fd);

	hsess->state = HSS_PARSING_HDR;
	hsess->request_hdr.nb_lines = 0;
	hsess->request_hdr.url_len = 0;
	hsess->request_hdr.url_overflow = 0;
	hsess->request_hdr.last_was_value = 1;
	hsess->request_hdr.lines_overflow = 0;
	hsess->chk_buf_idx = UINT_MAX;
	hsess->chk_buf_addr[0] = 0;
	hsess->chk_buf_addr[1] = 0;
#if defined SHFS_STATS && defined SHFS_STATS_HTTP && defined SHFS_STATS_HTTP_DPC
	hsess->stats.dpc_i = 0;
#endif
	http_parser_init(&hsess->parser, HTTP_REQUEST);
	httpsess_reset_keepalive(hsess);
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
	if (hs->nb_sess == hs->max_nb_sess) {
		err = ERR_MEM;
		goto err_out;
	}
	hsobj = mempool_pick(hs->sess_pool);
	if (!hsobj) {
		err = ERR_MEM;
		goto err_out;
	}
	hsess = hsobj->data;
	hsess->pobj = hsobj;
	hsess->hsrv = hs;
	hsess->chk_buf[0] = mempool_pick(shfs_vol.chunkpool);
	if (!hsess->chk_buf[0]) {
		err = ERR_MEM;
		goto err_free_hsobj;
	}
	hsess->chk_buf[1] = mempool_pick(shfs_vol.chunkpool);
	if (!hsess->chk_buf[1]) {
		err = ERR_MEM;
		goto err_free_chk_buf0;
	}
	hsess->sent_infly = 0;
	hsess->fd = NULL;
	hs->nb_sess++;

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

	/* reset session */
	hsess->chk_buf_aiotoken[0] = NULL;
	hsess->chk_buf_aiotoken[1] = NULL;
	httpsess_reset(hsess);

	dprintf("New HTTP session accepted\n");
	return 0;

 err_free_chk_buf0:
	mempool_put(hsess->chk_buf[0]);
 err_free_hsobj:
	mempool_put(hsobj);
 err_out:
	return err;
}

static err_t httpsess_close(struct http_sess *hsess, enum http_sess_close type)
{
#if HTTP_MULTISERVER
	struct http_srv *hs = hsess->hs;
#endif
	err_t err;

	ASSERT(hsess != NULL);

	/* disable tcp connection */
	tcp_arg(hsess->tpcb,  NULL);
	tcp_sent(hsess->tpcb, NULL);
	tcp_recv(hsess->tpcb, NULL);
	tcp_sent(hsess->tpcb, NULL);
	tcp_err(hsess->tpcb,  NULL);
	tcp_poll(hsess->tpcb, NULL, 0);

	/* close open file/wait for I/O exit */
	hsess->chk_buf_idx = UINT_MAX; /* disable calling of httpsess_response from aio cb */

	dprintf("Wait for unfinished I/O...\n");
	shfs_aio_wait(hsess->chk_buf_aiotoken[0]);
	shfs_aio_wait(hsess->chk_buf_aiotoken[1]);
	if (hsess->fd)
		shfs_fio_close(hsess->fd);
	dprintf("Done\n");

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
	mempool_put(hsess->chk_buf[1]);
	mempool_put(hsess->chk_buf[0]);
	mempool_put(hsess->pobj);
	--hs->nb_sess;

	dprintf("HTTP session %s (caller: 0x%x)\n", (type == HSC_ABORT ? "aborted" :
	                                             (type == HSC_CLOSE ? "closed" : "killed")), get_caller());
	return err;
}

static err_t httpsess_recv(void *argp, struct tcp_pcb *tpcb, struct pbuf *p, err_t err)
{
	struct http_sess *hsess = argp;
	struct pbuf *q;
	size_t plen;

	/* receive error: kill connection */
	if (unlikely(!p || err != ERR_OK)) {
		dprintf("Unexpected session error (p=%p, err=%d)\n", p, err);
		if (p) {
			/* inform TCP that we have taken the data */
			tcp_recved(tpcb, p->tot_len);
			pbuf_free(p);
		}
		/* close connection */
		return httpsess_close(hsess, HSC_ABORT);
	}

	switch (hsess->state) {
	case HSS_PARSING_HDR:
	case HSS_PARSING_MSG:
		/* feed parser */
		tcp_recved(tpcb, p->tot_len); /* we took the data */
		httpsess_disable_keepalive(hsess);
		for (q = p; q != NULL; q = q->next) {
			plen = http_parser_execute(&hsess->parser, hsess->parser_settings,
			                           q->payload, q->len);
			if (unlikely(hsess->parser.upgrade)) {
				/* protocol upgrade requested */
				dprintf("Unsupported HTTP protocol upgrade requested: Dropping connection...\n");
				return httpsess_close(hsess, HSC_CLOSE);
			}
			if (unlikely(plen != q->len)) {
				/* parsing error happened: close conenction */
				dprintf("HTTP protocol parsing error: Dropping connection...\n");
				return httpsess_close(hsess, HSC_CLOSE);
			}
			if (hsess->state == HSS_RESPONDING_HDR) {
				/* parser switch to next phase -> start with replying */
				return httpsess_respond(hsess);
			}
		}
		break;
	default:
		/* we are not done yet with replying
		 * or connection was aborted
		 * -> do not read input for now */
		break;
	}
	return ERR_OK;
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

	if (unlikely(hsess->keepalive_timer == 0))
		return httpsess_close(hsess, HSC_CLOSE); /* keepalive timeout: close connection */
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

	hsess->sent_infly -= len;
	switch (hsess->state) {
	case HSS_RESPONDING_HDR:
	case HSS_RESPONDING_MSG:
	case HSS_RESPONDING_EMSG:
		/* continue replying */
		if (len) {
			dprintf("Client acknowledged %u bytes, continue...\n", len);
			return httpsess_respond(hsess);
		}
		break;
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
	register size_t curpos, maxlen;

	curpos = hsess->request_hdr.url_len;
	maxlen = sizeof(hsess->request_hdr.url) - 1 - curpos;
	if (unlikely(len > maxlen)) {
		hsess->request_hdr.url_overflow = 1; /* Out of memory */
		len = maxlen;
	}
	MEMCPY(&hsess->request_hdr.url[curpos], buf, len);
	hsess->request_hdr.url_len += len;
	return 0;
}

static int httprecv_hdr_field(struct http_parser *parser, const char *buf, size_t len)
{
	struct http_sess *hsess = container_of(parser, struct http_sess, parser);
	register unsigned l;

	if (unlikely(hsess->request_hdr.lines_overflow))
		return 0; /* ignore line */
	if (unlikely(hsess->request_hdr.last_was_value)) {
		if (unlikely(hsess->request_hdr.nb_lines == HTTPHDR_REQ_MAXNB_LINES)) {
			/* overflow */
			hsess->request_hdr.lines_overflow = 1;
			return 0;
		}

		/* switch to next line and reset its buffer */
		hsess->request_hdr.last_was_value = 0;
		hsess->request_hdr.line[hsess->request_hdr.nb_lines].field.len = 0;
		hsess->request_hdr.line[hsess->request_hdr.nb_lines].value.len = 0;
		++hsess->request_hdr.nb_lines;
	}

	l = hsess->request_hdr.nb_lines - 1;
	_hdr_dbuffer_add(&hsess->request_hdr.line[l].field, buf, len);
	return 0;
}

static int httprecv_hdr_value(struct http_parser *parser, const char *buf, size_t len)
{
	struct http_sess *hsess = container_of(parser, struct http_sess, parser);
	register unsigned l;

	if (unlikely(hsess->request_hdr.lines_overflow))
		return 0; /* ignore line */
	if (unlikely(!hsess->request_hdr.last_was_value))
		hsess->request_hdr.last_was_value = 1; /* value parsing began */
	if (unlikely(hsess->request_hdr.nb_lines == 0))
		return -EINVAL; /* parsing error */

	l = hsess->request_hdr.nb_lines - 1;
	_hdr_dbuffer_add(&hsess->request_hdr.line[l].value, buf, len);
	return 0;
}

/* returns the field line number on success, -1 if it was not found */
static inline int http_reqhdr_findfield(struct http_sess *hsess, const char *field)
{
	register unsigned l;

	for (l = 0; l < hsess->request_hdr.nb_lines; ++l) {
		if (strncasecmp(field, hsess->request_hdr.line[l].field.b,
		                hsess->request_hdr.line[l].field.len) == 0) {
			return (int) l;
		}
	}

	return -1; /* not found */
}

/*******************************************************************************
 * HTTP Request handling
 ******************************************************************************/
#define ADD_RESHDR_SLINE(hsess, i, shdr_code)	  \
	do { \
		(hsess)->response_hdr.sline[(i)].b = _http_shdr[(shdr_code)]; \
		(hsess)->response_hdr.sline[(i)].len = _http_shdr_len[(shdr_code)]; \
		++(i); \
	} while(0)

#define ADD_RESHDR_DLINE(hsess, i, fmt, ...)	  \
	do { \
		(hsess)->response_hdr.dline[(i)].len = \
			snprintf((hsess)->response_hdr.dline[(i)].b, \
			         HTTPHDR_BUFFER_MAXLEN, \
			         (fmt), \
			         ##__VA_ARGS__); \
		++(i); \
	} while(0)

static int httprecv_req_complete(struct http_parser *parser)
{
	struct http_sess *hsess = container_of(parser, struct http_sess, parser);
	register uint32_t l;
	register size_t url_offset = 0;
	register int ret;
	register size_t nb_slines = 0;
	register size_t nb_dlines = 0;
#if defined SHFS_STATS && defined SHFS_STATS_HTTP && defined SHFS_STATS_HTTP_DPC
	register unsigned int i;
#endif

	/* Reset default values */
	hsess->keepalive = 0;

	/* finalize request_hdr lines by adding terminating '\0' */
	for (l = 0; l < hsess->request_hdr.nb_lines; ++l) {
		_hdr_dbuffer_terminate(&hsess->request_hdr.line[l].field);
		_hdr_dbuffer_terminate(&hsess->request_hdr.line[l].value);
	}
	hsess->request_hdr.url[hsess->request_hdr.url_len++] = '\0';

	dprintf("GET %s HTTP/%u.%u\n", hsess->request_hdr.url, parser->http_major, parser->http_minor);
	for (l = 0; l < hsess->request_hdr.nb_lines; ++l) {
		dprintf("   %s: %s\n",
		       hsess->request_hdr.line[l].field.b,
		       hsess->request_hdr.line[l].value.b);
	}

	/* try to open requested file and construct header */
	/* eliminate leading '/'s */
	while (hsess->request_hdr.url[url_offset] == '/')
		++url_offset;
	hsess->fd = shfs_fio_open(&hsess->request_hdr.url[url_offset]);
	if (!hsess->fd) {
		if (errno == ENOENT) {
			/* 404 File not found */
			hsess->response_hdr.code = 404;
			ADD_RESHDR_SLINE(hsess, nb_slines, HTTP_SHDR_404(parser->http_major, parser->http_minor));
			ADD_RESHDR_SLINE(hsess, nb_slines, HTTP_SHDR_HTML);
			ADD_RESHDR_SLINE(hsess, nb_slines, HTTP_SHDR_NOCACHE);
			ADD_RESHDR_SLINE(hsess, nb_slines, HTTP_SHDR_CONN_CLOSE);
			goto finalize_hdr;
		}

		/* 500 Internal server error */
		hsess->response_hdr.code = 500;
		ADD_RESHDR_SLINE(hsess, nb_slines, HTTP_SHDR_500(parser->http_major, parser->http_minor));
		ADD_RESHDR_SLINE(hsess, nb_slines, HTTP_SHDR_HTML);
		ADD_RESHDR_SLINE(hsess, nb_slines, HTTP_SHDR_NOCACHE);
		ADD_RESHDR_SLINE(hsess, nb_slines, HTTP_SHDR_CONN_CLOSE);
		goto finalize_hdr;
	}

	hsess->response_hdr.code = 200;	/* 200 OK */
	shfs_fio_size(hsess->fd, &hsess->fsize);
	shfs_fio_mime(hsess->fd, hsess->fmime, sizeof(hsess->fmime));
	shfs_fio_name(hsess->fd, hsess->fname, sizeof(hsess->fname));
#if defined SHFS_STATS && defined SHFS_STATS_HTTP
	hsess->stats.el_stats = shfs_stats_from_fd(hsess->fd);
#if defined SHFS_STATS_HTTP_DPC
	for (i = 0; i < SHFS_STATS_HTTP_DPCR; ++i)
		hsess->stats.dpc_threshold[i] = SHFS_STATS_HTTP_DPC_THRESHOLD(hsess->fsize, i);
#endif
#endif

	/* File range requested? */
	hsess->rfirst = 0;
	hsess->rlast  = hsess->fsize - 1;
	ret = http_reqhdr_findfield(hsess, "range");
	if (ret >= 0) {
		/* Because range requests require different answer codes
		 * (e.g., 206 OK or 416 EINVAL), we need to check the
		 * range request here already.
		 * http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.16 */
		hsess->response_hdr.code = 416;
		if (strncasecmp("bytes=", hsess->request_hdr.line[ret].value.b, 6) == 0) {
			uint64_t rfirst;
			uint64_t rlast;

			ret = sscanf(hsess->request_hdr.line[ret].value.b + 6,
			             "%lu-%lu",
			             &rfirst, &rlast);
			if (ret == 1) {
				/* only rfirst specified */
				if (rfirst < hsess->rlast) {
					hsess->rfirst = rfirst;
					hsess->response_hdr.code = 206;
				}
			} else if (ret == 2) {
				/* both, rfirst and rlast, specified */
				if ((rfirst < rlast) &&
				    (rfirst < hsess->rlast) &&
				    (rlast <= hsess->rlast)) {
					hsess->rfirst = rfirst;
					hsess->rlast = rlast;
					hsess->response_hdr.code = 206;
				}
			}
		}

		if (hsess->response_hdr.code == 416) {
			/* (parsing/out of range) error: response with 416 error header */
			dprintf("Could not parse range request\n");
			ADD_RESHDR_SLINE(hsess, nb_slines, HTTP_SHDR_416(parser->http_major, parser->http_minor));
			goto finalize_hdr;
		}

		dprintf("Client requested range of element: %lu-%lu\n",
		        hsess->rfirst, hsess->rlast);
	}

	/* HTTP OK [first line] (code can be 216 or 200) */
	if (hsess->response_hdr.code == 206)
		ADD_RESHDR_SLINE(hsess, nb_slines, HTTP_SHDR_206(parser->http_major, parser->http_minor));
	else
		ADD_RESHDR_SLINE(hsess, nb_slines, HTTP_SHDR_OK(parser->http_major, parser->http_minor));

	/* keepalive */
	if (http_should_keep_alive(&hsess->parser)) {
		hsess->keepalive = 1;
		ADD_RESHDR_SLINE(hsess, nb_slines, HTTP_SHDR_CONN_KEEPALIVE);
	} else {
		ADD_RESHDR_SLINE(hsess, nb_slines, HTTP_SHDR_CONN_CLOSE);
	}

	/* MIME (by element or default) */
	if (hsess->fmime[0] == '\0')
		ADD_RESHDR_SLINE(hsess, nb_slines, HTTP_SHDR_DEFAULT_TYPE);
	else
		ADD_RESHDR_DLINE(hsess, nb_dlines, "%s%s\r\n", _http_dhdr[HTTP_DHDR_MIME], hsess->fmime);

	/* Content length */
	hsess->rlen   = (hsess->rlast + 1) - hsess->rfirst;
	ADD_RESHDR_DLINE(hsess, nb_dlines, "%s%lu\r\n", _http_dhdr[HTTP_DHDR_SIZE], hsess->rlen);

	/* Content range */
	if (hsess->response_hdr.code == 206)
		ADD_RESHDR_DLINE(hsess, nb_dlines, "%s%lu-%lu/%lu\r\n",
		                 _http_dhdr[HTTP_DHDR_RANGE],
		                 hsess->rfirst, hsess->rlast, hsess->fsize);

	/* Initialize volchk range values for I/O */
	if (hsess->rlen != 0) {
		hsess->volchk_first = shfs_volchk_foff(hsess->fd, hsess->rfirst);                      /* first volume chunk of file */
		hsess->volchk_last  = shfs_volchk_foff(hsess->fd, hsess->rlast + hsess->rfirst);       /* last volume chunk of file */
		hsess->volchkoff_first = shfs_volchkoff_foff(hsess->fd, hsess->rfirst);                /* first byte in first chunk */
		hsess->volchkoff_last  = shfs_volchkoff_foff(hsess->fd, hsess->rlast + hsess->rfirst); /* last byte in last chunk */
	}

 finalize_hdr:
	/* Default header lines */
	ADD_RESHDR_SLINE(hsess, nb_slines, HTTP_SHDR_SERVER);
	ADD_RESHDR_SLINE(hsess, nb_slines, HTTP_SHDR_ACC_BYTERANGE);

	/* Calculate final header length */
	hsess->response_hdr.slines_tlen = 0;
	for (l = 0; l < nb_slines; ++l)
		hsess->response_hdr.slines_tlen += hsess->response_hdr.sline[l].len;
	hsess->response_hdr.dlines_tlen = 0;
	for (l = 0; l < nb_dlines; ++l)
		hsess->response_hdr.dlines_tlen += hsess->response_hdr.dline[l].len;
	hsess->response_hdr.eoh_off   = hsess->response_hdr.slines_tlen + hsess->response_hdr.dlines_tlen;
	hsess->response_hdr.total_len = hsess->response_hdr.eoh_off + _http_shdr_len[HTTP_EOH];
	hsess->response_hdr.nb_slines = nb_slines;
	hsess->response_hdr.nb_dlines = nb_dlines;

	/* Switch to reply phase (stops parser) */
	hsess->state = HSS_RESPONDING_HDR;
	hsess->sent  = 0;

	return 0;
}

/* might be called multiple times until hdr was sent out */
static inline err_t httpsess_write_hdr(struct http_sess *hsess, size_t *sent)
{
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
		if (apos < hsess->response_hdr.slines_tlen) {
			/* static header */
			aoff_nl = 0;
			for (l = 0; l < hsess->response_hdr.nb_slines; ++l) {
				aoff_cl  = aoff_nl;
				aoff_nl += hsess->response_hdr.sline[l].len;
				if ((aoff_cl <= apos) && (apos < aoff_nl)) {
					l_off  = apos - aoff_cl;
					l_left = hsess->response_hdr.sline[l].len - l_off;
					slen = min3(l_left, UINT16_MAX, avail);
					ptr  = (uint8_t *) hsess->response_hdr.sline[l].b + l_off;

					err     = httpsess_write(hsess, ptr, &slen, TCP_WRITE_FLAG_MORE);
					apos   += slen;
					avail  -= slen;
					l_left -= slen;
					if ((avail == 0) || (err != ERR_OK) || (l_left))
						goto out;
				}
			}
		}
		if ((apos >= hsess->response_hdr.slines_tlen) &&
		    (apos <  hsess->response_hdr.eoh_off)) {
			/* dynamic header */
			aoff_nl = hsess->response_hdr.slines_tlen;
			for (l = 0; l < hsess->response_hdr.nb_dlines; ++l) {
				aoff_cl  = aoff_nl;
				aoff_nl += hsess->response_hdr.dline[l].len;
				if ((aoff_cl <= apos) && (apos < aoff_nl)) {
					l_off  = apos - aoff_cl;
					l_left = hsess->response_hdr.dline[l].len - l_off;
					slen = min3(l_left, UINT16_MAX, avail);
					ptr  = (uint8_t *) hsess->response_hdr.dline[l].b + l_off;

					err     = httpsess_write(hsess, ptr, &slen, TCP_WRITE_FLAG_MORE);
					apos   += slen;
					avail  -= slen;
					l_left -= slen;
					if ((avail == 0) || (err != ERR_OK) || (l_left))
						goto out;
				}
			}
		}
		if (apos >= hsess->response_hdr.eoh_off) {
			/* end of header */
			l_off  = apos - hsess->response_hdr.eoh_off;
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
static void _httpsess_shfs_aiocb(SHFS_AIO_TOKEN *t, void *cookie, void *argp)
{
	struct http_sess *hsess = (struct http_sess *) cookie;
	register unsigned int idx = (unsigned int)(uintptr_t) argp;

	hsess->chk_buf_aioret[idx] = shfs_aio_finalize(t);
	hsess->chk_buf_aiotoken[idx] = NULL;

	/* continue sending process */
	if (idx == hsess->chk_buf_idx) {
		dprintf("** [idx=%u] request done, calling httpsess_respond()\n", idx);
		httpsess_respond(hsess);
	} else {
		dprintf("** [idx=%u] request done\n", idx);
                /* The TCP stack might be still waiting for more input
                 * of the previous chunk, but this guy does not get called any
                 * more: enforce it here */
                httpsess_flush(hsess);
	}
}

static inline int _httpsess_shfs_aioreq(struct http_sess *hsess, unsigned int idx)
{
	hsess->chk_buf_aiotoken[idx] = shfs_aread_chunk(hsess->chk_buf_addr[idx], 1,
	                                                hsess->chk_buf[idx]->data,
	                                                _httpsess_shfs_aiocb,
	                                                hsess,
	                                                (void *)(uintptr_t) idx);
	if (unlikely(!hsess->chk_buf_aiotoken[idx])) {
		dprintf("failed setting up request for [idx=%u]!\n", idx);
		return -errno;
	}
	dprintf("request set up for [idx=%u]\n", idx);
	return 0;
}

static inline err_t httpsess_write_shfsafio(struct http_sess *hsess, size_t *sent)
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

	idx = hsess->chk_buf_idx;
	roff = *sent; /* offset in request */
	foff = roff + hsess->rfirst;  /* offset in file */
	cur_chk = shfs_volchk_foff(hsess->fd, foff);
 next:
	err = ERR_OK;

	if (idx == UINT_MAX || cur_chk != hsess->chk_buf_addr[idx]) {
		/* we got called for the first time
		 * or requested chunk is not loaded yet (for whatever reason) */
		if (idx == UINT_MAX)
			idx = 0;
		hsess->chk_buf_addr[idx] = cur_chk;
		ret = _httpsess_shfs_aioreq(hsess, idx);
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

	if (hsess->chk_buf_aiotoken[idx] != NULL) {
		/* current request is not done yet,
		 * we need to wait. httpsess_response
		 * will be recalled from within callback */
		dprintf("[idx=%u] current request is not done yet\n", idx);
		goto out;
	}

	/* time for doing a read ahead? */
	next_chk = cur_chk + 1;
	next_idx = (idx + 1) & 0x01; /* (idx + 1) % 2 */
	if (hsess->chk_buf_addr[next_idx] != next_chk &&
	    next_chk <= hsess->volchk_last) {
		/* try to do the read ahaed
		 * on errors, there will by a retry set up */
		hsess->chk_buf_addr[next_idx] = next_chk;
		ret = _httpsess_shfs_aioreq(hsess, next_idx);
		if (unlikely(ret < 0))
			hsess->chk_buf_addr[next_idx] = 0; /* trigger retry */
	}

	/* send out data from chk buffer that is loaded already */
	avail = tcp_sndbuf(hsess->tpcb);
	if (unlikely(avail == 0)) {
		/* we need to wait for free space on tcp sndbuf
		 * httpsess_response is recalled when client has
		 * acknowledged its received data */
		dprintf("[idx=%u] tcp send buffer is full\n", idx);
		goto out;
	}
	chk_off = shfs_volchkoff_foff(hsess->fd, foff);
	left = min(shfs_vol.chunksize - chk_off, hsess->rlen - roff);
	slen = min3(UINT16_MAX, avail, left);
	err = httpsess_write(hsess, ((uint8_t *) (hsess->chk_buf[idx]->data)) + chk_off,
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
		cur_chk = shfs_volchk_foff(hsess->fd, foff);
		if (hsess->chk_buf_aiotoken[idx] == NULL &&
		    hsess->chk_buf_addr[idx] == cur_chk) {
			hsess->chk_buf_idx = idx;
			dprintf("httpsess_write_shfsafio: next chunk [idx=%u] is ready already, " \
			        "resume processing\n", idx);
			goto next;
		} else {
			dprintf("httpsess_write_shfsafio: next chunk [idx=%u] not ready yet\n", idx);
		}
	}
 out:
	hsess->chk_buf_idx = idx;
	return err;

 err_abort:
	return err;
}

/* sync I/O */
static inline err_t httpsess_write_shfssfio(struct http_sess *hsess, size_t *sent)
{
	register size_t foff = (uint64_t) *sent;  /* offset in file */
	register uint16_t avail;
	size_t left;                              /* left bytes of file */
	uint16_t slen;
	err_t err;
	int ret;

	avail = tcp_sndbuf(hsess->tpcb);
	if (unlikely(avail == 0))
		return ERR_OK; /* we need to wait for space on tcp sndbuf */
	left = hsess->fsize;
	left -= foff;
	slen = min4(left, UINT16_MAX, shfs_vol.chunksize, avail);

	ret = shfs_fio_read(hsess->fd, foff, hsess->chk_buf[0]->data, slen);
	if (ret < 0) {
		return ERR_BUF; /* I/O error */
	}
	err = httpsess_write(hsess, hsess->chk_buf[0]->data, &slen, TCP_WRITE_FLAG_MORE | TCP_WRITE_FLAG_COPY);

	*sent += slen;
	return err;
}

/* closes a http session or wait for next request by client
 * if keepalive was requested */
static inline err_t httpsess_eof(struct http_sess *hsess)
{
	httpsess_flush(hsess);

	if (hsess->keepalive) {
		/* wait for next request */
		httpsess_reset(hsess);
		return ERR_OK;
	}

	/* close connection */
	return httpsess_close(hsess, HSC_CLOSE);
}

/* Send out http response
 * Note: Will be called multiple times while a request is handled */
static err_t httpsess_respond(struct http_sess *hsess)
{
	size_t len;
	err_t err = ERR_OK;

	switch (hsess->state) {
	case HSS_RESPONDING_HDR:
		/* send out header */
		err = httpsess_write_hdr(hsess, &hsess->sent);
		if (unlikely(err))
			goto err_close;

		if (hsess->sent == hsess->response_hdr.total_len) {
			/* we are done */
			if (hsess->response_hdr.code >= 200 &&
			    hsess->response_hdr.code < 300) {
				/* response body (file) */
				hsess->state = HSS_RESPONDING_MSG;
				hsess->sent = 0;
			} else if (hsess->response_hdr.code == 404 ||
			           hsess->response_hdr.code >= 500) {
				/* error body */
				hsess->state = HSS_RESPONDING_EMSG;
				hsess->sent = 0;
			} else {
				/* no body */
				err = httpsess_eof(hsess);
				if (err != ERR_OK)
					return err;
			}
		}
		break;

	case HSS_RESPONDING_EMSG:
		/* send out error message */
		switch (hsess->response_hdr.code) {
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
			err = httpsess_eof(hsess);
			if (err != ERR_OK)
				return err;
		}
		break;

	case HSS_RESPONDING_MSG:
		/* send out data */
		err = httpsess_write_shfsafio(hsess, &hsess->sent);
		if (unlikely(err))
			goto err_close;

#if defined SHFS_STATS && defined SHFS_STATS_HTTP && defined SHFS_STATS_HTTP_DPC
		while (unlikely(hsess->sent >= hsess->stats.dpc_threshold[hsess->stats.dpc_i]))
			++hsess->stats.el_stats->p[hsess->stats.dpc_i++];
#endif

		if (unlikely(hsess->sent == hsess->rlen)) {
			/* we are done */
#if defined SHFS_STATS && defined SHFS_STATS_HTTP
			++hsess->stats.el_stats->c; /* successfully completed request */
#endif
			err = httpsess_eof(hsess);
			if (err != ERR_OK)
				return err;
		}
		break;

	default:
		/* unknown state?! */
		goto err_close;
	}
	return ERR_OK;

 err_close:
	/* error happened -> kill connection */
	return httpsess_close(hsess, HSC_ABORT);
}
