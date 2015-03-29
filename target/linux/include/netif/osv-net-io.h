/*
 * C++/C wrapper for OSv networking
 */

#ifndef __OSV_NET_IO__
#define __OSV_NET_IO__
#ifdef __cplusplus
#include <string>

extern "C"
{
#endif

struct pbuf; /* defined in lwIP */

typedef struct _onio onio;

/* if name==NULL, first available device is opened */
onio *open_onio(const char *ifname,
		struct pbuf *(*mk_pbuf)(const unsigned char *, int),
		void (*free_pbuf)(struct pbuf *),
		void (*rxcb)(struct pbuf *, void *), void *rxcb_argp);
void close_onio(onio *dev);

int onio_transmit(onio *dev, void *buf, size_t len);
void onio_poll(onio *dev);

size_t onio_get_hwaddr(onio *dev, void *addr_out, size_t maxlen);

#ifdef __cplusplus
}
#endif
#endif /* __OSV_NET_IO__ */
