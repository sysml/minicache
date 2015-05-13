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

struct http_req_link_origin {
	dlist_el(uplink_chain);

	struct shfs_cache_entry *cce[HTTPREQ_LINK_MAXNB_BUFFERS];  

	/* TODO: put a list of clinets here */
	struct http_req_link_state *client;
};

static inline void httpreq_link_prepare_hdr(struct http_req *hreq)
{
	return;
}

static inline int httpreq_link_build_hdr(struct http_req *hreq)
{
	return 0;
}

#endif /* _HTTP_LINK_H_ */
