/*
 * thpHTTP - A tiny high performance HTTP server for Mini-OS
 *  This HTTP server is based on http_parser.
 *
 * Copyright(C) 2014 NEC Laboratories Europe. All rights reserved.
 *                   Simon Kuenzer <simon.kuenzer@neclab.eu>
 */
#ifndef _HTTP_H_
#define _HTTP_H_

#define HTTP_LISTEN_PORT          80
#define HTTP_TCP_PRIO             TCP_PRIO_MAX
#define HTTP_MULTISERVER          0

#if HTTP_MULTISERVER
struct http_srv;
#endif

#if HTTP_MULTISERVER
struct http_srv *init_http(int nb_sess, uint16_t port);
void exit_http(struct http_srv *hs);
#else
int init_http(int nb_sess);
void exit_http(void);
#endif

#endif
