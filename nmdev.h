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

struct nmdev_slot
{
    struct netmap_slot *slot;
    void *bffr;
};

struct nmdev_ring 
{
    struct netmap_ring *ring;
    uint32_t slots_infly;
};

struct nmdev
{
    int fd;
    struct pollfd pfd;
    struct netmap_priv_d *priv;
    struct netmap_xinfo *xinfo;
    struct netmap_if *nifp;
    struct eth_addr mac;

    struct nmdev_ring txring;
    struct nmdev_ring rxring;
};

struct nmdev *open_nmdev(unsigned int vif_id);
void close_nmdev(struct nmdev *nm);

#define nmdev_mac(nm) (&((nm)->mac))

#define nmdev_avail_txslots(nm) ((nm)->txring.ring->avail - (nm)->txring.slots_infly)

/*
 * Picks a number of tx slots from netmap's rings
 * The function returns the actual number of picked slots from netmap buffers
 */
static inline uint32_t nmdev_pick_txslots(struct nmdev *nm, struct nmdev_slot txslots[], uint32_t count)
{
    uint32_t i;
    struct netmap_ring *ring;
    unsigned int cur;

    ring = nm->txring.ring;
    count = min(count, nmdev_avail_txslots(nm));

    /* pick available buffers */
    cur = (ring->cur + nm->txring.slots_infly) % ring->num_slots;
    for (i = 0; i < count; i++) {
        txslots[i].slot = &ring->slot[cur];
        txslots[i].bffr = NETMAP_BUF(nm->xinfo, cur);
        cur = NETMAP_RING_NEXT(ring, cur);
    }
    nm->txring.slots_infly += count;
    return count;
}

/*
 * Puts a tx packet buffer back to netmap and sent the packet out
 */
static inline void nmdev_xmit_txslots(struct nmdev *nm, uint32_t count)
{
    struct netmap_ring *ring;
    
    ASSERT(count <= nm->txring.slots_infly);

    ring = nm->txring.ring;
    ring->avail -= count;
    ring->cur = (ring->cur + count) % ring->num_slots;
    nm->txring.slots_infly -= count;

    /* trigger netmap to send */
    nm->pfd.events = (POLLOUT);
    poll(&nm->pfd, 1, 0);
}

#define nmdev_avail_rxslots(nm) ((nm)->rxring.ring->avail - (nm)->rxring.slots_infly)

//static inline nmdev_put_rxslot()
//{
//}
//
//static inline nmdev_recv_rxlot()
//{
//}

/* Returns the number of transmitted packets */
static inline uint32_t nmdev_xmit_burst(struct nmdev *nm, struct pktbuf **pkts, uint32_t count)
{
    struct nmdev_slot txslots[count];
    uint32_t i;
    count = min(count, nmdev_avail_txslots(nm));

    nmdev_pick_txslots(nm, txslots, count);
    for (i = 0; i < count; ++i) {
        txslots[i].slot->len = pkts[i]->pktlen;
        txslots[i].slot->flags = 0;
        pkt_copy(pkts[i]->p_obj.data, txslots[i].bffr, pkts[i]->pktlen);
    }
    nmdev_xmit_txslots(nm, count);
    pktpool_put_multiple(pkts, count);

    return count;
}

#define nmdev_xmit(nm, pkt) (nmdev_xmit_burst((nm), &(pkt), 1) ? 0 : -1)

#endif /* _NMDEV_H_ */
