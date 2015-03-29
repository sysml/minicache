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

typedef struct _onio onio;

/* if name==NULL, first available device is opened */
onio *open_onio(const char *ifname, void (*rxcb)(void *, int, void *), void *rxcb_arg);
void close_onio(onio *dev);

int onio_transmit(onio *dev, void *pkt, size_t len);
void onio_poll(onio *dev);

size_t onio_get_hwaddr(onio *dev, void *addr_out, size_t maxlen);

#ifdef __cplusplus
}
#endif
#endif /* __OSV_NET_IO__ */
