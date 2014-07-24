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

int init_http(uint16_t nb_sess, uint32_t nb_reqs);
void exit_http(void);

#endif
