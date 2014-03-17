/*
 * thpHTTP - A tiny high performance HTTP server for Mini-OS
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

#include "http_parser.h"
#include "http_data.h"
#include "http.h"

#define HTTP_LISTEN_PORT 81
#define HTTP_TCP_PRIO TCP_PRIO_MAX
#define HTTP_POLL_INTERVAL 10 /* = x * 500ms; 10 = 5s */

#define HTTPHDR_BUFFER_MAXLEN 64
#define HTTPHDR_MAX_NB_LINES 8

#ifndef min
#define min(a, b) \
    ({ __typeof__ (a) __a = (a); \
       __typeof__ (b) __b = (b); \
       __a < __b ? __a : __b; })
#endif

enum http_sess_state {
	HSS_UNDEF = 0,
	HSS_PARSING_HDR,
	HSS_PARSING_MSG,
	HSS_RESPONDING_HDR,
	HSS_RESPONDING_MSG,
	HSS_CLOSING,
};

struct http_srv {
	struct tcp_pcb *tpcb;
	struct mempool *sess_pool;
	uint32_t nb_sess;
	uint32_t max_nb_sess;
};

struct _hdr_buffer {
	char b[HTTPHDR_BUFFER_MAXLEN];
	size_t len;
};

struct _hdr_line {
	struct _hdr_buffer field;
	struct _hdr_buffer value;
};

struct http_sess {
	struct mempool_obj *pobj;
	struct http_srv *hsrv;
	struct tcp_pcb *tpcb;

	enum http_sess_state state;
	struct http_parser parser;
	struct http_parser_settings parser_settings;

	struct {
		struct _hdr_buffer url;
		struct _hdr_line line[HTTPHDR_MAX_NB_LINES];
		uint32_t nb_lines;
		int last_was_value;
		int lines_overflow; /* more lines in request header than memory available */
	} request_hdr;

	size_t infly;
};

static struct http_srv *hs = NULL;

static err_t httpsess_accept (void *argp, struct tcp_pcb *new_tpcb, err_t err);
static void  httpsess_close  (struct http_sess *hsess);
static err_t httpsess_sent   (void *argp, struct tcp_pcb *tpcb, uint16_t len);
static err_t httpsess_recv   (void *argp, struct tcp_pcb *tpcb, struct pbuf *p, err_t err);
static void  httpsess_error  (void *argp, err_t err);
static err_t httpsess_poll   (void *argp, struct tcp_pcb *tpcb);
static void  httpsess_respond(struct http_sess *hsess);

int init_http(int nb_sess)
{
	err_t err;
	int ret = 0;

	hs = _xmalloc(sizeof(*hs), PAGE_SIZE);
	if (!hs) {
		ret = -ENOMEM;
		goto err_out;
	}
	hs->max_nb_sess = nb_sess;
	hs->nb_sess = 0;

	/* allocate session pool */
	hs->sess_pool = alloc_simple_mempool(hs->max_nb_sess,
	                                     sizeof(struct http_sess));
	if (!hs->sess_pool) {
		ret = -ENOMEM;
		goto err_free_hs;
	}

	/* register TCP listener */
	hs->tpcb = tcp_new();
	if (!hs->tpcb) {
		ret = -ENOMEM;
		goto err_free_sesspool;
	}
	err = tcp_bind(hs->tpcb, IP_ADDR_ANY, HTTP_LISTEN_PORT);
	if (err != ERR_OK) {
		ret = -ENOMEM;
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
	return ret;
}

void exit_http(void)
{
	tcp_close(hs->tpcb);
	free_mempool(hs->sess_pool);
	xfree(hs);
	hs = NULL;
}


/*******************************************************************************
 * Session handling
 ******************************************************************************/
static int httprecv_req_complete(struct http_parser *parser);
static int httprecv_hdr_url(struct http_parser *parser, const char *buf, size_t len);
static int httprecv_hdr_field(struct http_parser *parser, const char *buf, size_t len);
static int httprecv_hdr_value(struct http_parser *parser, const char *buf, size_t len);

static err_t httpsess_accept(void *argp, struct tcp_pcb *new_tpcb, err_t err)
{
	struct mempool_obj *hsobj;
	struct http_sess *hsess;
	//struct http_srv *hs = argp;

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
	hsess->infly = 0;
	hs->nb_sess++;

	hsess->request_hdr.nb_lines = 0;
	hsess->request_hdr.url.len = 0;
	hsess->request_hdr.last_was_value = 1;
	hsess->request_hdr.lines_overflow = 0;

	/* register tpcb */
	hsess->tpcb = new_tpcb;
	hsess->state = HSS_PARSING_HDR;
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
	http_parser_init(&hsess->parser, HTTP_REQUEST);

	return 0;

 err_out:
	return err;
}

static void httpsess_close(struct http_sess *hsess)
{
	//struct http_srv *hs = hsess->hs;

	/* disable tcp connection */
	tcp_arg(hsess->tpcb,  NULL);
	tcp_sent(hsess->tpcb, NULL);
	tcp_recv(hsess->tpcb, NULL);
	tcp_sent(hsess->tpcb, NULL);
	tcp_err(hsess->tpcb,  NULL);
	tcp_poll(hsess->tpcb, NULL, 0);

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
	if (!p || err != ERR_OK) {
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
		for (q = p; q != NULL; q = q->next) {
			plen = http_parser_execute(&hsess->parser, &hsess->parser_settings,
			                           q->payload, q->len);
			if (unlikely(hsess->parser.upgrade)) {
				/* protocol upgrade requested */
				printf("Unsupported HTTP protocol upgrade requested: Killing connection...\n");
				httpsess_close(hsess);
			}
			if (unlikely(plen != q->len)) {
				/* parsing error happened: close conenction */
				printf("HTTP protocol parsing error: Dropping connection...\n");
				httpsess_close(hsess);
			}
		}
		tcp_recved(tpcb, p->tot_len); /* we took the data */
		break;
	default:
		/* we are not done yet with replying
		 * or connection was aborted
		 * -> do not */
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
	return ERR_OK;
}

/** Call tcp_write() in a loop trying smaller and smaller length
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

	hsess->infly += l;
	*len = l;
	return err;
}

static err_t httpsess_sent(void *argp, struct tcp_pcb *tpcb, uint16_t len) {
	struct http_sess *hsess = argp;

	hsess->infly -= len;
	switch (hsess->state) {
	case HSS_RESPONDING_HDR:
	case HSS_RESPONDING_MSG:
		/* continue replying */
		httpsess_respond(hsess);
		break;
	case HSS_CLOSING:
		/* close session after all sent data were ack'ed */
		if (likely(hsess->infly == 0))
			httpsess_close(hsess);
		break;
	default:
		break;
	}

	return ERR_OK;
}

/*******************************************************************************
 * HTTP Request header parsing
 ******************************************************************************/
static void _hdr_buffer_add(struct _hdr_buffer *dst, const char *src, size_t len)
{
	register size_t curpos, maxlen;

	curpos = dst->len;
	maxlen = sizeof(dst->b) - 1 - curpos; /* -1 to store terminating '\0' later */

	len = min(maxlen, len);
	memcpy(&dst->b[curpos], src, len);
	dst->len += len;
}

static void _hdr_buffer_terminate(struct _hdr_buffer *dst)
{
	dst->b[dst->len++] = '\0';
}

static int httprecv_hdr_url(struct http_parser *parser, const char *buf, size_t len)
{
	struct http_sess *hsess = parser->data;
	_hdr_buffer_add(&hsess->request_hdr.url, buf, len);
	return 0;
}

static int httprecv_hdr_field(struct http_parser *parser, const char *buf, size_t len)
{
	struct http_sess *hsess = parser->data;
	register unsigned lineno;

	if (unlikely(hsess->request_hdr.lines_overflow))
		return 0; /* ignore line */
	if (unlikely(hsess->request_hdr.last_was_value)) {
		if (unlikely(hsess->request_hdr.nb_lines == HTTPHDR_MAX_NB_LINES)) {
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

	lineno = hsess->request_hdr.nb_lines - 1;
	_hdr_buffer_add(&hsess->request_hdr.line[lineno].field, buf, len);
	return 0;
}

static int httprecv_hdr_value(struct http_parser *parser, const char *buf, size_t len)
{
	struct http_sess *hsess = parser->data;
	register unsigned lineno;

	if (unlikely(hsess->request_hdr.lines_overflow))
		return 0; /* ignore line */
	if (unlikely(!hsess->request_hdr.last_was_value))
		hsess->request_hdr.last_was_value = 1; /* value parsing began */
	if (unlikely(hsess->request_hdr.nb_lines == 0))
		return -EINVAL; /* parsing error */

	lineno = hsess->request_hdr.nb_lines - 1;
	_hdr_buffer_add(&hsess->request_hdr.line[lineno].value, buf, len);
	return 0;
}

/*******************************************************************************
 * HTTP Request handling
 ******************************************************************************/
static int httprecv_req_complete(struct http_parser *parser)
{
	struct http_sess *hsess = parser->data; /* TODO: Use containerof: less lookups? */
	register unsigned lineno;

	/* finalize request_hdr lines by adding terminating '\0' */
	for (lineno = 0; lineno < hsess->request_hdr.nb_lines; ++lineno) {
		_hdr_buffer_terminate(&hsess->request_hdr.line[lineno].field);
		_hdr_buffer_terminate(&hsess->request_hdr.line[lineno].value);
	}
	_hdr_buffer_terminate(&hsess->request_hdr.url);

	/* DEBUG */
	printf("Got HTTP/%u.%u header!\n", parser->http_major, parser->http_minor);
	for (lineno = 0; lineno < hsess->request_hdr.nb_lines; ++lineno) {
		printf(" %s: %s\n",
		       hsess->request_hdr.line[lineno].field.b,
		       hsess->request_hdr.line[lineno].value.b);
	}
	printf("URL: %s\n", hsess->request_hdr.url.b);
	/* DEBUG */

	hsess->state = HSS_RESPONDING_HDR; /* switch to reply mode */
	httpsess_respond(hsess);
	return 0;
}

/* will be called multiple times */
static void httpsess_respond(struct http_sess *hsess)
{
	static const char resp_hdr[] =
		"HTTP/1.1 404 File not found\r\n"
		"Server: "HTTPD_SERVER_AGENT"\r\n"
		"Content-type: text/plain\r\n"
		"\r\n";
	uint16_t len = (uint16_t) sizeof(resp_hdr) - 1;

	switch (hsess->state) {
	case HSS_RESPONDING_HDR:
		/* send out header */
		httpsess_write(hsess, resp_hdr, &len, 0);
		hsess->state = HSS_CLOSING; /* let the session close after sending */
	case HSS_RESPONDING_MSG:
		/* send out data */
		break;
	default:
		break;
	}
}

/*******************************************************************************
 * File I/O
 ******************************************************************************/
