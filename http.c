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
#include "http.h"

#define HTTP_LISTEN_PORT 81
#define HTTP_TCP_PRIO TCP_PRIO_MAX
#define HTTP_POLL_INTERVAL 10 /* = x * 500ms; 10 = 5s */

enum http_sess_state {
	HSS_UNDEF = 0,
	HSS_ESTABLISHED,
	HSS_CLOSING,
};

struct http_srv {
	struct tcp_pcb *tpcb;
	struct mempool *sess_pool;
	uint32_t nb_sess;
	uint32_t max_nb_sess;

	struct http_parser_settings parser_settings;
};

struct http_sess {
	struct mempool_obj *pobj;
	struct http_srv *hsrv;
	struct tcp_pcb *tpcb;

	enum http_sess_state state;
	struct http_parser parser;
};

static struct http_srv *hs = NULL;


static err_t httpsess_accept(void *argp, struct tcp_pcb *new_tpcb, err_t err);
static void  httpsess_close (struct http_sess *hsess);
static err_t httpsess_recv  (void *argp, struct tcp_pcb *tpcb, struct pbuf *p, err_t err);
static void  httpsess_error (void *argp, err_t err);
static err_t httpsess_poll  (void *argp, struct tcp_pcb *tpcb);

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
	hs->nb_sess++;

	/* register tpcb */
	hsess->tpcb = new_tpcb;
	hsess->state = HSS_ESTABLISHED;
	tcp_arg (hsess->tpcb, hsess); /* argp for callbacks */
	tcp_recv(hsess->tpcb, httpsess_recv); /* recv callback */
	tcp_sent(hsess->tpcb, NULL); /* sent ack callback */
	tcp_err (hsess->tpcb, httpsess_error); /* err callback */
	tcp_poll(hsess->tpcb, httpsess_poll, HTTP_POLL_INTERVAL); /* poll callback */
	tcp_setprio(hsess->tpcb, HTTP_TCP_PRIO);

	/* init parser */
	http_parser_init(&hsess->parser, HTTP_BOTH);

	return 0;

	// err_putobj:
	//	mempool_put(hsobj);
 err_out:
	return err;
}

static void httpsess_close(struct http_sess *hsess)
{
	/* disable tcp connection */
	tcp_arg(hsess->tpcb, NULL);
	tcp_sent(hsess->tpcb, NULL);
	tcp_recv(hsess->tpcb, NULL);
	tcp_sent(hsess->tpcb, NULL);
	tcp_err(hsess->tpcb, NULL);
	tcp_poll(hsess->tpcb, NULL, 0);

	/* release memory */
	tcp_close(hsess->tpcb);
	mempool_put(hsess->pobj);
}

static err_t httpsess_recv(void *argp, struct tcp_pcb *tpcb, struct pbuf *p, err_t err)
{
	struct http_sess *hsess = argp;
	return ERR_OK;
}

static void httpsess_error(void *argp, err_t err)
{
	struct http_sess *hsess = argp;
	httpsess_close(hsess);
}

/* Is called every 5 sec */
static err_t httpsess_poll(void *argp, struct tcp_pcb *tpcb)
{
	struct http_sess *hsess = argp;
	return ERR_OK;
}


/*******************************************************************************
 * HTTP protocol handling
 ******************************************************************************/
