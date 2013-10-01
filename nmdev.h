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
#ifndef min3
#define min3(a, b ,c) (min(min((a), (b)), (c)))
#endif
#ifndef min4
#define min4(a, b ,c, d) (min(min((a), (b)), min((c), (d))))
#endif

struct nmbuf
{
    void *data;
    size_t len;
};

struct _nmdev_ring 
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

    struct _nmdev_ring txring;
    struct _nmdev_ring rxring;
};

struct nmdev *open_nmdev(unsigned int vif_id);
void close_nmdev(struct nmdev *nm);

#define nmdev_mac(nm) (&((nm)->mac))

#define _nmdev_do_poll(nm, event)      \
    do {                               \
        (nm)->pfd.events = (event);    \
        poll(&(nm)->pfd, 1, 0);        \
    } while(0)
#define nmdev_pollin(nm)  _nmdev_do_poll((nm),  (POLLIN))
#define nmdev_pollout(nm) _nmdev_do_poll((nm),  (POLLOUT))
#define nmdev_poll(nm)    _nmdev_do_poll((nm), ((POLLIN) | (POLLOUT)))

#define nmdev_avail_txbufs(nm) ((nm)->txring.ring->avail - (nm)->txring.slots_infly)

/*
 * Picks a number of tx buffers from netmap
 * The function returns the actual number of picked slots from netmap buffers
 */
static inline uint32_t nmdev_pick_txbufs(struct nmdev *nm, struct nmbuf txbufs[], uint32_t count)
{
    uint32_t i;
    struct netmap_ring *ring;
    unsigned int cur;

    ring = nm->txring.ring;
    count = min(count, nmdev_avail_txbufs(nm));

    /* pick available buffers */
    cur = (ring->cur + nm->txring.slots_infly) % ring->num_slots;
    for (i = 0; i < count; i++) {
        txbufs[i].data = NETMAP_BUF(nm->xinfo, cur);
        txbufs[i].len  = ring->slot[cur].len;
        cur = NETMAP_RING_NEXT(ring, cur);
    }
    nm->txring.slots_infly += count;
    return count;
}

/*
 * Puts a tx packet buffers back to netmap
 */
static inline void nmdev_put_txbufs(struct nmdev *nm, uint32_t count)
{
    struct netmap_ring *ring;
    
    ASSERT(count <= nm->txring.slots_infly);

    ring = nm->txring.ring;
    ring->avail -= count;
    ring->cur    = (ring->cur + count) % ring->num_slots;
    nm->txring.slots_infly -= count;
}

#define nmdev_avail_rxbufs(nm) ((nm)->rxring.ring->avail - (nm)->rxring.slots_infly)

static inline uint32_t nmdev_pick_rxbufs(struct nmdev *nm, struct nmbuf rxbufs[], uint32_t count)
{
    uint32_t i;
    struct netmap_ring *ring;
    unsigned int cur;

    ring = nm->rxring.ring;
    count = min(count, nmdev_avail_rxbufs(nm));

    /* pick available buffers */
    cur = (ring->cur + nm->rxring.slots_infly) % ring->num_slots;
    for (i = 0; i < count; i++) {
        rxbufs[i].data = NETMAP_BUF(nm->xinfo, cur);
        rxbufs[i].len  = ring->slot[cur].len;
        cur = NETMAP_RING_NEXT(ring, cur);
    }
    nm->rxring.slots_infly += count;
    return count;
}

static inline void nmdev_put_rxbufs(struct nmdev *nm, uint32_t count)
{
    struct netmap_ring *ring;

    ASSERT(count <= nm->rxring.slots_infly);

    ring = nm->rxring.ring;
    ring->avail -= count;
    ring->cur    = (ring->cur + count) % ring->num_slots;
    nm->rxring.slots_infly -= count;
}

/********************************************
 * netdev.c/netdev.h like interfaces
 */

/* Returns the number of transmitted packets */
static inline uint32_t nmdev_xmit_burst(struct nmdev *nm, struct pktbuf **pkts, uint32_t count)
{
    struct nmbuf txbufs[count];
    uint32_t i;
    count = min(count, nmdev_avail_txbufs(nm));

    nmdev_pick_txbufs(nm, txbufs, count);
    for (i = 0; i < count; ++i) {
        txbufs[i].len = pkts[i]->pktlen;
        pkt_copy(pkts[i]->p_obj.data, txbufs[i].data, pkts[i]->pktlen);
    }
    nmdev_put_txbufs(nm, count);
    nmdev_pollout(nm); /* trigger netmap for sending */
    pktpool_put_multiple(pkts, count);

    return count;
}

#define nmdev_xmit(nm, pkt) (nmdev_xmit_burst((nm), &(pkt), 1) ? 0 : -1)

static inline uint32_t nmdev_recv_burst(struct nmdev *nm, struct pktbuf **pkts, uint32_t count, struct mempool *pktpool)
{
    struct nmbuf rxbufs[count];
    uint32_t i;
    
    nmdev_pollin(nm);
    count = min3(count, nmdev_avail_rxbufs(nm), pktpool_free_count(pktpool));

    pktpool_pick_multiple(pktpool, pkts, count);
    nmdev_pick_rxbufs(nm, rxbufs, count);
    for (i = 0; i < count; ++i) {
        pkts[i]->pktlen = rxbufs[i].len;
        pkt_copy(rxbufs[i].data, pkts[i]->p_obj.data, rxbufs[i].len);
    }
    nmdev_put_rxbufs(nm, count);

    return count;
}

static inline struct pktbuf *nmdev_recv(struct nmdev *nm, struct mempool *pktpool)
{
    struct pktbuf *pkt;
    uint32_t ret;
    
    ret = nmdev_recv_burst(nm, &pkt, 1, pktpool);
    if (likely(ret))
        return pkt;
    return NULL;
}

#endif /* _NMDEV_H_ */
