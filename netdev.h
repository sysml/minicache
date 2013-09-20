#ifndef _NETDEV_H_
#define _NETDEV_H_

#ifdef CONFIG_NETMAP_XENBUS
#include <mini-os/nm_netfront.h>
#else
#include <mini-os/netfront.h>
#endif /* NETMAP_NETFRONT */
#include "pktbuf.h"
#include "hexdump.h"

struct netdev {
  struct netfront_dev *dev;
  struct eth_addr mac;
};

struct netdev *open_netdev(unsigned int vif_id);
void close_netdev(struct netdev *nd);
#define netdev_mac(nd) (&((nd)->mac))

static inline int netdev_xmit(struct netdev *nd, struct pktbuf *pkt)
{
  netfront_xmit(nd->dev, pkt->p_obj.data, pkt->pktlen);
  pktpool_put(pkt);
  return 0;
}

/*
 * Note: Packets need to be allocated from the same pktpool
 */
static inline uint32_t netdev_xmit_burst(struct netdev *nd, struct pktbuf **pkts, uint32_t count)
{
  uint32_t i;
  for (i=0; i<count; i++)
	netfront_xmit(nd->dev, pkts[i]->p_obj.data, pkts[i]->pktlen);
  pktpool_put_multiple(pkts, count);
  return count;
}

#endif /* _NETDEV_H_ */
