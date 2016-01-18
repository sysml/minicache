#ifndef _HTTP_DEFS_H_
#define _HTTP_DEFS_H_

#include <target/sys.h>
#include <lwip/tcp.h>
#include <lwip/dns.h>
#include <errno.h>
#include "likely.h"

#include "http_parser.h"
#include "http_data.h"
#include "http_hdr.h"

#include "mempool.h"
#if defined SHFS_STATS && defined SHFS_STATS_HTTP
#include "shfs_stats.h"
#endif
#include "dlist.h"

#include "shfs.h"
#include "shfs_cache.h"
#include "shfs_fio.h"
#include "shfs_tools.h"

#ifdef HTTP_DEBUG
#define ENABLE_DEBUG
#endif
#include "debug.h"

#define HTTP_LISTEN_PORT          80
#define HTTP_TCP_PRIO             TCP_PRIO_MAX
#define HTTP_MAXNB_LINKS          4 /* nb of simultaneous links to an origin server */
#define HTTP_LINK_TCP_PRIO        TCP_PRIO_MAX

#define HTTP_POLL_INTERVAL        10 /* = x * 500ms; 10 = 5s */
#define HTTP_KEEPALIVE_TIMEOUT     3 /* = x * HTTP_POLL_INTERVAL */
#define HTTP_TCPKEEPALIVE_TIMEOUT 90 /* = x sec */
#define HTTP_TCPKEEPALIVE_IDLE    30 /* = x sec */

#define HTTP_LINK_CONNECT_TIMEOUT   3 /* = x sec */
#define HTTP_LINK_RESPONSE_TIMEOUT 10 /* = x sec */
#define HTTP_LINK_RECEIVE_TIMEOUT  30 /* = x sec */

#define HTTPHDR_URL_MAXLEN        99 /* MAX: '/' + '?' + 512 bits hash + '\0' */
#define HTTPURL_ARGS_INDICATOR   '?'

#define HTTPREQ_SNDBUF            ((size_t) TCP_SND_BUF)

#if ((TCP_WND) > (TCP_SND_BUF))
#warning "lwIP's TCP send buffer is smaller than the TCP window: Bad TCP/IP performance is expected."
#define HTTPREQ_LOW_SNDBUF
#endif

#ifndef SMAX
#define SMAX(x, y) ((x) > (y) ? (x) : (y))
#endif

#define HTTPREQ_FIO_MAXNB_BUFFERS         (SMAX(2,(DIV_ROUND_UP(HTTPREQ_SNDBUF, SHFS_MIN_CHUNKSIZE))))
#define HTTPREQ_LINK_MAXNB_BUFFERS        (SMAX(2,((DIV_ROUND_UP(HTTPREQ_SNDBUF, SHFS_MIN_CHUNKSIZE)) << 1)))

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
#ifndef max
#define max(a, b) \
    ({ __typeof__ (a) __a = (a); \
       __typeof__ (b) __b = (b); \
       __a > __b ? __a : __b; })
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
	struct mempool *link_pool;

	uint16_t nb_sess;
	uint16_t max_nb_sess;
	uint32_t nb_reqs;
	uint32_t max_nb_reqs;
	uint16_t nb_links;
	uint16_t max_nb_links;

	struct http_sess *hsess_head;
	struct http_sess *hsess_tail;

	struct dlist_head links;
	struct dlist_head ioretry_chain;
};

extern struct http_srv *hs;

enum http_sess_state {
	HSS_UNDEF = 0,
	HSS_ESTABLISHED,
	HSS_CLOSING
};

struct http_sess {
	struct http_sess *next;
	struct http_sess *prev;

	struct mempool_obj *pobj;
	struct http_srv *hsrv;
	struct tcp_pcb *tpcb;
	enum http_sess_state state;
	size_t sent_infly;
	size_t sent;

	struct http_parser parser;

	int keepalive;
	int keepalive_timer; /* -1 timeout disabled, 0 timeout expired */

	struct http_req *cpreq; /* current request that is parsed */
	struct http_req *rqueue_head; /* request serve queue of parsed requests */
	struct http_req *rqueue_tail;
	struct http_req *aqueue_head; /* acknowledge queue (requests that are done with sending out but not yet acknowledged) */
	struct http_req *aqueue_tail;
	unsigned int rqueue_len; /* current number of simultaneous requests */

	int retry_replychain; /* marker for rare cases: reply could not be initiated
	                       * within recv because of ERR_MEM */
	int _in_respond;      /* diables recursive httpsess_respond calls DELETEME */
	dlist_el(ioretry_chain);

	//struct http_srv *hs;
};

enum http_req_state {
	HRS_UNDEF = 0,
	HRS_PARSING_HDR,
	HRS_PARSING_MSG,
	HRS_PREPARING_HDR,
	HRS_BUILDING_HDR,
	HRS_FINALIZING_HDR,
	HRS_RESPONDING_HDR,
	HRS_RESPONDING_MSG,
	HRS_RESPONDING_EOM
};

enum http_req_type {
	HRT_UNDEF = 0,
	HRT_SMSG,      /* static message body */
#ifdef HTTP_TESTFILE
	HRT_SMSG_INF,  /* static message body, but infinite */
#endif
	HRT_FIOMSG,    /* dynamic message body (file from shfs) */
	HRT_LINKMSG,   /* dynamic message body (uplink described by shfs) */
	HRT_NOMSG,     /* just response header, no body */
};

struct http_req_fio_state { /* defined in http_fio.h */
	/* SHFS I/O */
	uint64_t fsize; /* file size */
	uint64_t rfirst; /* (requested) first byte to read from file */
	uint64_t rlast;  /* (requested) last byte to read from file */
	chk_t volchk_first;
	chk_t volchk_last;
	uint32_t volchkoff_first;
	uint32_t volchkoff_last;

	struct shfs_cache_entry *cce[HTTPREQ_FIO_MAXNB_BUFFERS];
	SHFS_AIO_TOKEN *cce_t;
	unsigned int cce_idx;
	unsigned int cce_idx_ack;
	unsigned int cce_max_nb;
};

struct http_req_link_origin; /* defined in http_link.h */

struct http_req_link_state {
	struct http_req_link_origin *origin;
	size_t pos;
	unsigned int cce_idx;
	size_t acked_pos;

	dlist_el(clients);
};

struct http_req {
	struct mempool_obj *pobj;
	struct http_sess *hsess;
	struct http_req *next;
	enum http_req_state state;
	enum http_req_type type;

	struct {
		uint8_t http_major;
		uint8_t http_minor;
		uint8_t http_errno;
		uint8_t method;
		int keepalive;
		char url[HTTPHDR_URL_MAXLEN];
		size_t url_len;
		int url_overflow;
		char *url_argp; /* ptr to argument in url */
		struct http_recv_hdr hdr;
	} request;

	struct {
		uint16_t code;
		struct http_send_hdr hdr;
		size_t hdr_eoh_off; /* end of header offset */
		size_t hdr_total_len; /* total length (inclusive EOH line) */
		size_t hdr_acked_len; /* acked bytes from header */
		size_t ftr_acked_len; /* acked bytes from footer */
	} response;

	uint64_t rlen; /* (requested) number of bytes of message body */
	uint64_t alen; /* (acknowledged) number of bytes (of rlen) */
	int is_stream; /* is true when final data length is unknown while sending */

	/* Static buffer I/O */
	const char *smsg;

	SHFS_FD fd;
	union {
		struct http_req_fio_state  f;
		struct http_req_link_state l;
	};

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

#define httpsess_register_ioretry(hsess) \
	do { \
		if (!dlist_is_linked((hsess), \
		                     hs->ioretry_chain, \
		                     ioretry_chain)) { \
			dlist_append((hsess), \
			             hs->ioretry_chain, \
			             ioretry_chain); \
		} \
	} while(0)

#define httpsess_unregister_ioretry(hsess) \
	do { \
		if (unlikely(dlist_is_linked((hsess), \
		                             hs->ioretry_chain, \
		                             ioretry_chain))) { \
			dlist_unlink((hsess), \
			             hs->ioretry_chain, \
			             ioretry_chain); \
		} \
	} while(0)

#define httpsess_flush(hsess) tcp_output((hsess)->tpcb)

err_t httpsess_write(struct http_sess *hsess, const void* buf, size_t *len, uint8_t apiflags);
err_t httpsess_respond(struct http_sess *hsess);

#endif /* _HTTP_DEFS_H_ */
