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

#include "http_parser.h"
#include "http_data.h"
#include "http.h"

#define HTTP_POLL_INTERVAL        10 /* = x * 500ms; 10 = 5s */
#define HTTP_KEEPALIVE_TIMEOUT     3 /* = x * HTTP_POLL_INTERVAL */

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
	HSS_CLOSING,
};

struct http_srv {
	struct tcp_pcb *tpcb;
	struct mempool *sess_pool;
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
	struct http_parser_settings parser_settings;

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
	int keepalive_timer; /* -1, timout disabled, 0 timeout expired */

	SHFS_FD fd;
	char fmime[65]; /* mime type of file (fd) */
	char fname[65]; /* name of file (fd) */
	uint64_t fsize; /* file size (fd) */
	char chk_buf[]; /* memory allocated by alloc_mempool */
};

#if !(HTTP_MULTISERVER)
static struct http_srv *hs = NULL;
#endif

static err_t httpsess_accept (void *argp, struct tcp_pcb *new_tpcb, err_t err);
static void  httpsess_close  (struct http_sess *hsess);
static err_t httpsess_sent   (void *argp, struct tcp_pcb *tpcb, uint16_t len);
static err_t httpsess_recv   (void *argp, struct tcp_pcb *tpcb, struct pbuf *p, err_t err);
static void  httpsess_error  (void *argp, err_t err);
static err_t httpsess_poll   (void *argp, struct tcp_pcb *tpcb);
static err_t httpsess_respond(struct http_sess *hsess);

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
	hs->sess_pool = alloc_simple_mempool(hs->max_nb_sess,
	                                     sizeof(struct http_sess) +
	                                     shfs_vol.chunksize);
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

	return ret;

 err_free_tcp:
	tcp_close(hs->tpcb);
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
static int httprecv_req_complete(struct http_parser *parser);
static int httprecv_hdr_url(struct http_parser *parser, const char *buf, size_t len);
static int httprecv_hdr_field(struct http_parser *parser, const char *buf, size_t len);
static int httprecv_hdr_value(struct http_parser *parser, const char *buf, size_t len);

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

	/* init parser */
	hsess->parser_settings.on_message_begin = NULL;
	hsess->parser_settings.on_url = httprecv_hdr_url;
	hsess->parser_settings.on_status = NULL;
	hsess->parser_settings.on_header_field = httprecv_hdr_field;
	hsess->parser_settings.on_header_value = httprecv_hdr_value;
	hsess->parser_settings.on_headers_complete = NULL;
	hsess->parser_settings.on_body = NULL;
	hsess->parser_settings.on_message_complete = httprecv_req_complete;
	hsess->parser.data = hsess;

	/* reset session */
	httpsess_reset(hsess);

	return 0;

 err_out:
	return err;
}

static void httpsess_close(struct http_sess *hsess)
{
#if HTTP_MULTISERVER
	struct http_srv *hs = hsess->hs;
#endif

	/* disable tcp connection */
	tcp_arg(hsess->tpcb,  NULL);
	tcp_sent(hsess->tpcb, NULL);
	tcp_recv(hsess->tpcb, NULL);
	tcp_sent(hsess->tpcb, NULL);
	tcp_err(hsess->tpcb,  NULL);
	tcp_poll(hsess->tpcb, NULL, 0);

	/* close open file */
	if (hsess->fd)
		shfs_fio_close(hsess->fd);

	/* release memory */
	tcp_close(hsess->tpcb);
	mempool_put(hsess->pobj);
	--hs->nb_sess;
}

static err_t httpsess_recv(void *argp, struct tcp_pcb *tpcb, struct pbuf *p, err_t err)
{
	struct http_sess *hsess = argp;
	struct pbuf *q;
	size_t plen;

	/* receive error: close connection */
	if (unlikely(!p || err != ERR_OK)) {
		if (p) {
			/* inform TCP that we have taken the data */
			tcp_recved(tpcb, p->tot_len);
			pbuf_free(p);
		}
		/* close connection */
		httpsess_close(hsess);
		return ERR_OK;
	}

	switch (hsess->state) {
	case HSS_PARSING_HDR:
	case HSS_PARSING_MSG:
		/* feed parser */
		tcp_recved(tpcb, p->tot_len); /* we took the data */
		httpsess_disable_keepalive(hsess);
		for (q = p; q != NULL; q = q->next) {
			plen = http_parser_execute(&hsess->parser, &hsess->parser_settings,
			                           q->payload, q->len);
			if (unlikely(hsess->parser.upgrade)) {
				/* protocol upgrade requested */
				printf("Unsupported HTTP protocol upgrade requested: Dropping connection...\n");
				httpsess_close(hsess);
			}
			if (unlikely(plen != q->len)) {
				/* parsing error happened: close conenction */
				printf("HTTP protocol parsing error: Dropping connection...\n");
				httpsess_close(hsess);
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
	httpsess_close(hsess); /* close connection */
}

/* Is called every 5 sec */
static err_t httpsess_poll(void *argp, struct tcp_pcb *tpcb)
{
	struct http_sess *hsess = argp;

	if (unlikely(hsess->keepalive_timer == 0))
		httpsess_close(hsess); /* timeout expired: close connection */
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
		/* continue replying */
		httpsess_respond(hsess);
		break;
	case HSS_CLOSING:
		/* close session after all sent data were ack'ed */
		if (likely(hsess->sent_infly == 0))
			httpsess_close(hsess);
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

/*******************************************************************************
 * HTTP Request handling
 ******************************************************************************/
static int httprecv_req_complete(struct http_parser *parser)
{
	struct http_sess *hsess = container_of(parser, struct http_sess, parser);
	register uint32_t l;
	register unsigned shdr_code;
	register size_t url_offset = 0;

	/* finalize request_hdr lines by adding terminating '\0' */
	for (l = 0; l < hsess->request_hdr.nb_lines; ++l) {
		_hdr_dbuffer_terminate(&hsess->request_hdr.line[l].field);
		_hdr_dbuffer_terminate(&hsess->request_hdr.line[l].value);
	}
	hsess->request_hdr.url[hsess->request_hdr.url_len++] = '\0';

/* DEBUG
	printf("Got HTTP/%u.%u header!\n", parser->http_major, parser->http_minor);
	for (l = 0; l < hsess->request_hdr.nb_lines; ++l) {
		printf(" %s: %s\n",
		       hsess->request_hdr.line[l].field.b,
		       hsess->request_hdr.line[l].value.b);
	}
	printf(" GET: %s\n", hsess->request_hdr.url.b);
DEBUG */

	/* try to open requested file and construct header */
	/* eliminate leading '/'s */
	while (hsess->request_hdr.url[url_offset] == '/')
		++url_offset;
	hsess->fd = shfs_fio_open(&hsess->request_hdr.url[url_offset]);
	if (!hsess->fd) {
		if (errno == ENOENT) {
			/* 404 File not found */
			shdr_code = HTTP_SHDR_404(parser->http_major, parser->http_minor);
			hsess->response_hdr.code         = 404;
			hsess->response_hdr.sline[0].b   = _http_shdr    [shdr_code];
			hsess->response_hdr.sline[0].len = _http_shdr_len[shdr_code];
			hsess->response_hdr.sline[1].b   = _http_shdr    [HTTP_SHDR_HTML];
			hsess->response_hdr.sline[1].len = _http_shdr_len[HTTP_SHDR_HTML];
			hsess->response_hdr.sline[2].b   = _http_shdr    [HTTP_SHDR_NOCACHE];
			hsess->response_hdr.sline[2].len = _http_shdr_len[HTTP_SHDR_NOCACHE];
			hsess->response_hdr.sline[3].b   = _http_shdr    [HTTP_SHDR_CONN_CLOSE];
			hsess->response_hdr.sline[3].len = _http_shdr_len[HTTP_SHDR_CONN_CLOSE];
			hsess->response_hdr.nb_slines    = 4;
			hsess->response_hdr.nb_dlines    = 0;
		} else {
			/* 500 Internal server error */
			shdr_code = HTTP_SHDR_500(parser->http_major, parser->http_minor);
			hsess->response_hdr.code         = 500;
			hsess->response_hdr.sline[0].b   = _http_shdr    [shdr_code];
			hsess->response_hdr.sline[0].len = _http_shdr_len[shdr_code];
			hsess->response_hdr.sline[1].b   = _http_shdr    [HTTP_SHDR_HTML];
			hsess->response_hdr.sline[1].len = _http_shdr_len[HTTP_SHDR_HTML];
			hsess->response_hdr.sline[2].b   = _http_shdr    [HTTP_SHDR_NOCACHE];
			hsess->response_hdr.sline[2].len = _http_shdr_len[HTTP_SHDR_NOCACHE];
			hsess->response_hdr.sline[3].b   = _http_shdr    [HTTP_SHDR_CONN_CLOSE];
			hsess->response_hdr.sline[3].len = _http_shdr_len[HTTP_SHDR_CONN_CLOSE];
			hsess->response_hdr.nb_slines    = 4;
			hsess->response_hdr.nb_dlines    = 0;
		}
	} else {
		/* 200 OK */
		hsess->response_hdr.code = 200;
		shfs_fio_size(hsess->fd, &hsess->fsize);
		shfs_fio_mime(hsess->fd, hsess->fmime, sizeof(hsess->fmime));
		shfs_fio_name(hsess->fd, hsess->fname, sizeof(hsess->fname));

		shdr_code = HTTP_SHDR_OK(parser->http_major, parser->http_minor);
		hsess->response_hdr.sline[0].b   = _http_shdr    [shdr_code];
		hsess->response_hdr.sline[0].len = _http_shdr_len[shdr_code];
		if (http_should_keep_alive(&hsess->parser)) {
			hsess->keepalive = 1;
			hsess->response_hdr.sline[1].b   = _http_shdr    [HTTP_SHDR_CONN_KEEPALIVE];
			hsess->response_hdr.sline[1].len = _http_shdr_len[HTTP_SHDR_CONN_KEEPALIVE];
		} else {
			hsess->keepalive = 0;
			hsess->response_hdr.sline[1].b   = _http_shdr    [HTTP_SHDR_CONN_CLOSE];
			hsess->response_hdr.sline[1].len = _http_shdr_len[HTTP_SHDR_CONN_CLOSE];
		}
		hsess->response_hdr.nb_slines    = 2;

		hsess->response_hdr.dline[0].len = snprintf(hsess->response_hdr.dline[0].b,
		                                            HTTPHDR_BUFFER_MAXLEN,
		                                            "%s%s\r\n",
		                                            _http_dhdr[HTTP_DHDR_MIME],
		                                            hsess->fmime);
		hsess->response_hdr.dline[1].len = snprintf(hsess->response_hdr.dline[1].b,
		                                            HTTPHDR_BUFFER_MAXLEN,
		                                            "%s%lu\r\n",
		                                            _http_dhdr[HTTP_DHDR_SIZE],
		                                            hsess->fsize);
		hsess->response_hdr.nb_dlines    = 2;
	}

	/* Server string */
	hsess->response_hdr.sline[hsess->response_hdr.nb_slines  ].b   = _http_shdr    [HTTP_SHDR_SERVER];
	hsess->response_hdr.sline[hsess->response_hdr.nb_slines++].len = _http_shdr_len[HTTP_SHDR_SERVER];

	/* final header length */
	hsess->response_hdr.slines_tlen = 0;
	for (l = 0; l < hsess->response_hdr.nb_slines; ++l)
		hsess->response_hdr.slines_tlen += hsess->response_hdr.sline[l].len;
	hsess->response_hdr.dlines_tlen = 0;
	for (l = 0; l < hsess->response_hdr.nb_dlines; ++l)
		hsess->response_hdr.dlines_tlen += hsess->response_hdr.dline[l].len;
	hsess->response_hdr.eoh_off   = hsess->response_hdr.slines_tlen + hsess->response_hdr.dlines_tlen;
	hsess->response_hdr.total_len = hsess->response_hdr.eoh_off + _http_shdr_len[HTTP_EOH];

	/* start transmission */
	hsess->state = HSS_RESPONDING_HDR; /* switch to reply phase (disables parser) */
	hsess->sent  = 0;
	httpsess_respond(hsess);
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
	httpsess_flush(hsess);
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

static inline err_t httpsess_write_shfsfio(struct http_sess *hsess, size_t *sent)
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

	ret = shfs_fio_read(hsess->fd, foff, hsess->chk_buf, slen);
	if (ret < 0) {
		return ERR_BUF; /* I/O error */
	}
	err = httpsess_write(hsess, hsess->chk_buf, &slen, TCP_WRITE_FLAG_MORE | TCP_WRITE_FLAG_COPY);

	*sent += slen;
	return err;
}

/* will be called multiple times */
static err_t httpsess_respond(struct http_sess *hsess)
{
	size_t len;
	err_t err = ERR_OK;

	switch (hsess->state) {
	case HSS_RESPONDING_HDR:
		/* send out header */
		err = httpsess_write_hdr(hsess, &hsess->sent);

		/* sending of hdr done? */
		if (hsess->sent < hsess->response_hdr.total_len)
			break; /* no */
		httpsess_flush(hsess);
		hsess->sent = 0;
		if (hsess->response_hdr.code == 200) {
			hsess->state = HSS_RESPONDING_MSG;
			break;
		} else {
			hsess->state = HSS_RESPONDING_EMSG;
		}
	case HSS_RESPONDING_EMSG:
		/* send out error message */
		switch (hsess->response_hdr.code) {
		case 404:
			len = _http_err404p_len;
			err = httpsess_write_sbuf(hsess, &hsess->sent, _http_err404p, len);
			break;
		case 501:
			len = _http_err501p_len;
			err = httpsess_write_sbuf(hsess, &hsess->sent, _http_err501p, len);
			break;
		default:
			len = _http_err500p_len;
			err = httpsess_write_sbuf(hsess, &hsess->sent, _http_err500p, len);
			break;
		}

		if (hsess->sent == len) {
			/* we are done serving the request */
			hsess->state = HSS_CLOSING;
		}
		break;
	case HSS_RESPONDING_MSG:
		/* send out data */
		err = httpsess_write_shfsfio(hsess, &hsess->sent);

		if (hsess->sent == hsess->fsize) {
			/* we are done serving the request */
			if (hsess->keepalive)
				httpsess_reset(hsess);
			else
				hsess->state = HSS_CLOSING;
		}
		break;
	default:
		/* unknown state -> close connection */
		hsess->state = HSS_CLOSING;
		break;
	}

	return err;
}
