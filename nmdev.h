#ifndef _NMDEV_H_
#define _NMDEV_H_

#include <sys/poll.h>
#include <netmap/netmap.h>
#include <netmap/netmap_user.h>
#include <netif/etharp.h>
#include <mini-os/pkt_copy.h>

#include "pktbuf.h"
#include "debug.h"

#ifndef min
#define min(a, b) (((a) < (b)) ? (a) : (b))
#endif



struct nmdev
{
    int fd;
    struct pollfd pfd;
    struct netmap_priv_d *priv;
    struct netmap_if *nifp;
    struct netmap_ring *txring;
    struct netmap_ring *rxring;
    struct eth_addr mac;
};

struct nmdev *open_nmdev(unsigned int vif_id);
void close_nmdev(struct nmdev *nm);

#define nmdev_mac(nm) (&((nm)->mac))

/* Returns the number of transmitted packets */
static inline uint32_t nmdev_xmit_burst(struct nmdev *nm, struct pktbuf **pkts, uint32_t count)
{
    uint32_t i;
    struct netmap_slot *slot;
    struct netmap_ring *txring;
    struct netmap_xinfo *xinfo;
    unsigned int cur;
    void *bffr;

    txring = nm->txring;
    xinfo = &nm->priv->tx_desc;
    count = min(count, nm->txring->avail);
    
    
    /* copy packet buffers to netmap buffers */
    cur = txring->cur;
    for (i = 0; i < count; ++i) {
        slot = &txring->slot[cur];
        slot->len = pkts[i]->pktlen;
        slot->flags = 0; /* clear flags */

        bffr = NETMAP_BUF(xinfo, cur);
        pkt_copy(pkts[i]->p_obj.data, bffr, slot->len);    

        cur = NETMAP_RING_NEXT(txring, cur);
    }
    txring->avail -= count;
    txring->cur = cur;

    /* trigger netmap to send */
    nm->pfd.events = (POLLOUT);
    poll(&nm->pfd, 1, 0);
    
    pktpool_put_multiple(pkts, count);
    return count;
}

static inline int nmdev_xmit(struct nmdev *nm, struct pktbuf *pkt)
{
    return (nmdev_xmit_burst(nm, &pkt, 1) ? 0 : -1);
}

#endif /* _NMDEV_H_ */
