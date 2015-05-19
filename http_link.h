/*
 * thpHTTP - A tiny high performance HTTP server for Mini-OS
 *  This HTTP server is based on http_parser.
 *
 * Copyright(C) 2014-2015 NEC Laboratories Europe. All rights reserved.
 *                        Simon Kuenzer <simon.kuenzer@neclab.eu>
 */
#ifndef _HTTP_LINK_H_
#define _HTTP_LINK_H_

#include "http_defs.h"

#define httpreq_link_nb_buffers(chunksize)  ((max((DIV_ROUND_UP(HTTPREQ_TCP_MAXSNDBUF, (size_t) chunksize)), 2)) << 1)

enum http_req_link_origin_state {
	HRLO_UNKNOWN = 0,
	HRLO_ERROR,
	HRLO_RESOLVE,
	HRLO_WAIT_RESOLVE,
	HRLO_CONNECT,
	HRLO_WAIT_CONNECT,
	HRLO_REQUEST,
	HRLO_WAIT_REPLY,
	HRLO_STREAMING
};

struct http_req_link_origin {
	struct tcp_pcb *tpcb;
	ip_addr_t rip;
	uint16_t rport;
	uint16_t timeout;

	dlist_el(links);
	dlist_head(clients);
	uint32_t nb_clients;

	enum http_req_link_origin_state state;
	struct shfs_cache_entry *cce[HTTPREQ_LINK_MAXNB_BUFFERS];

	struct mempool_obj *pobj;
};

int   httplink_init   (struct http_srv *hs);
void  httplink_exit   (struct http_srv *hs);
//void  httplink_close  (struct http_req_link_origin *o);
err_t httplink_connected(void *argp, struct tcp_pcb * tpcb, err_t err);
err_t httplink_sent   (void *argp, struct tcp_pcb *tpcb, uint16_t len);
err_t httplink_recv   (void *argp, struct tcp_pcb *tpcb, struct pbuf *p, err_t err);
void  httplink_error  (void *argp, err_t err);
err_t httplink_poll   (void *argp, struct tcp_pcb *tpcb);

static inline void httplink_update_clients(struct http_req_link_origin *o)
{
  struct http_req *hreq;
  struct http_req *hreq_next;

  hreq = dlist_first_el(o->clients, typeof(*hreq));
  while(hreq) {
    hreq_next = dlist_next_el(hreq, l.clients);
    printd("Notifying client %p (hsess %p)\n", hreq, hreq->hsess);
    httpsess_respond(hreq->hsess);
    hreq = hreq_next;
  }
}

static inline int httpreq_link_prepare_hdr(struct http_req *hreq)
{
	//struct http_srv *hs = hreq->hsess->hs;
	struct mempool_obj *pobj;
	struct http_req_link_origin *o;

	o = shfs_fio_get_cookie(hreq->fd);
	if (o) {
		/* append this request to client list (join) */
		dlist_append(hreq, o->clients, l.clients);
		hreq->l.origin = o;
		++o->nb_clients;

		printd("origin found %p, request %p joined\n", o, hreq);
		return 0;
	}

	/* create a new upstream link */
	pobj = mempool_pick(hs->link_pool);
	if (!pobj)
		goto err_out;
	o = (struct http_req_link_origin *) pobj->data;
	o->pobj = pobj;

	o->tpcb = tcp_new();
	if (!o->tpcb)
		goto err_free_o;
	o->state = HRLO_RESOLVE;
	tcp_arg(o->tpcb, o);
	tcp_recv(o->tpcb, httplink_recv); /* recv callback */
	tcp_sent(o->tpcb, httplink_sent); /* sent ack callback */
	tcp_err (o->tpcb, httplink_error); /* err callback */
	tcp_poll(o->tpcb, httplink_poll, HTTP_POLL_INTERVAL); /* poll callback */
	tcp_setprio(o->tpcb, HTTP_LINK_TCP_PRIO);

	/* append origin to list of origins */
	dlist_init_el(o, links);
	dlist_append(o, hs->links, links);
	++hs->nb_links;

	/* append this request to client list */
	dlist_init_head(o->clients);
	dlist_append(hreq, o->clients, l.clients);
	hreq->l.origin = o;
	o->nb_clients = 1;

	/* add cookie to file descriptor (never fails) */
	shfs_fio_set_cookie(hreq->fd, o);

	printd("new origin %p with request %p created\n", o, hreq);
	return 0;

 err_free_o:
	mempool_put(pobj);
 err_out:
	return -ENOMEM;
}

void httpreq_link_dnscb(const char *name, ip_addr_t *ipaddr, void *argp);

static inline int httpreq_link_build_hdr(struct http_req *hreq)
{
	//struct http_srv *hs = hreq->hsess->hs;
	struct http_req_link_origin *o = hreq->l.origin;
	err_t err;
	int ret;

	/* connection procedure */
	switch(o->state) {
	case HRLO_RESOLVE:
	  /* resolv remote host name */
	  printd("Resolving origin host address...\n");
	  o->rport = shfs_fio_link_rport(hreq->fd);
	  ret = shfshost2ipaddr(shfs_fio_link_rhost(hreq->fd), &o->rip, httpreq_link_dnscb, hreq);
	  if (ret < 0) {
	    printd("Resolution of origin host address failed: %d\n", ret);
	    goto err_out;
	  }
	  if (ret >= 1) {
	    o->state = HRLO_WAIT_RESOLVE;
	    return -EAGAIN;
	  }
	  printd("Resolution could be done directly\n");
	  o->state = HRLO_CONNECT;
	  goto case_HRLO_CONNECT;

	case_HRLO_CONNECT:
	case HRLO_CONNECT:
	  /* connect to remote */
	  printd("Connecting to origin host...\n");
	  o->timeout = HTTP_LINK_CONNECT_TIMEOUT;
	  err = tcp_connect(o->tpcb, &o->rip, o->rport, httplink_connected);
	  if (err != ERR_OK)
	    goto err_out;
	  o->state = HRLO_WAIT_CONNECT;
	  return -EAGAIN;

	case HRLO_REQUEST:
	  o->timeout = HTTP_LINK_REPLY_TIMEOUT;
	  goto err_out; /* for now */

	case HRLO_ERROR:
	  goto err_out;
	default: /* HRLO_WAIT_RESOLVE, HRLO_WAIT_CONNECTED */
	  return -EAGAIN; /* stay in phase */
	}

	/* build response */
	return 0; /* next phase */

 err_out: /* will end up in err500_hdr */
	printd("Error exit\n");
	o->state = HRLO_ERROR;
	return -1;
}

static inline void httpreq_link_close(struct http_req *hreq)
{
	//struct http_srv *hs = hreq->hsess->hs;
	struct http_req_link_origin *o = hreq->l.origin;

	--o->nb_clients;
	dlist_unlink(&hreq->l, o->clients, clients);
	printd("request %p removed from origin %p\n", hreq, o);
	if (o->nb_clients == 0) {
		/* close connection to origin */
		shfs_fio_clear_cookie(hreq->fd);
		--hs->nb_links;
		dlist_unlink(o, hs->links, links);

		if (o->tpcb)
		  tcp_abort(o->tpcb);

		mempool_put(o->pobj);
		printd("origin %p destroyed\n", o);
	}
}

#endif /* _HTTP_LINK_H_ */
