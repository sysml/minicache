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
	HRLO_CONNECT,
	HRLO_WAIT,
	HRLO_CONNECTED,
};

struct http_req_link_origin {
	struct mempool_obj *pobj;
	dlist_el(links);
	dlist_head(clients);
	uint32_t nb_clients;

	enum http_req_link_origin_state state;
	struct shfs_cache_entry *cce[HTTPREQ_LINK_MAXNB_BUFFERS];
};

int http_link_init(struct http_srv *hs);
void http_link_exit(struct http_srv *hs);

static inline int httpreq_link_prepare_hdr(struct http_req *hreq)
{
	//struct http_srv *hs = hreq->hsess->hs;
	struct mempool_obj *pobj;
	struct http_req_link_origin *o;

	o = shfs_fio_get_cookie(hreq->fd);
	if (o) {
		/* append this request to client list (join) */
		dlist_init_head(o->clients);
		dlist_append(&hreq->l, o->clients, clients);

		hreq->l.origin = o;
		++o->nb_clients;
		return 0;
	}

	/* create a new upstream link */
	pobj = mempool_pick(hs->link_pool);
	if (!pobj)
		return -ENOMEM;
	o = (struct http_req_link_origin *) pobj->data;
	o->pobj = pobj;

	/* add cookie to file descriptor (never fails) */
	shfs_fio_set_cookie(hreq->fd, o);

	/* append origin to list of origins */
	dlist_init_el(o, links);
	dlist_append(o, hs->links, links);
	++hs->nb_links;

	/* append this request to client list */
	dlist_append(&hreq->l, o->clients, clients);

	/* initial state */
	o->state = HRLO_CONNECT;

	hreq->l.origin = o;
	o->nb_clients = 1;
	return 0;
}

static inline int httpreq_link_build_hdr(struct http_req *hreq)
{
	//struct http_srv *hs = hreq->hsess->hs;
	struct http_req_link_origin *o = hreq->l.origin;

	if (o->state != HRLO_CONNECTED)
		return -EAGAIN; /* stay in phase */

	/* build response */
	return 0; /* next phase */
}

static inline void httpreq_link_close(struct http_req *hreq)
{
	//struct http_srv *hs = hreq->hsess->hs;
	struct http_req_link_origin *o = hreq->l.origin;

	--o->nb_clients;
	dlist_unlink(&hreq->l, o->clients, clients);
	if (o->nb_clients == 0) {
		/* close connection to origin */
		shfs_fio_clear_cookie(hreq->fd);
		--hs->nb_links;
		dlist_unlink(o, hs->links, links);

		mempool_put(o->pobj);
	}
}

#endif /* _HTTP_LINK_H_ */
