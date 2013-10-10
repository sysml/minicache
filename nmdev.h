#ifndef _NMDEV_H_
#define _NMDEV_H_

#include <netmap/netmap.h>
#include <netmap/netmap_user.h>
#include <netmap/netmap_kern.h>
#include <netif/etharp.h>
#include <mini-os/pkt_copy.h>
#include <mini-os/events.h>

#include "pktbuf.h"

#ifndef min
#define min(a, b) \
    ({ __typeof__ (a) __a = (a); \
       __typeof__ (b) __b = (b); \
       __a < __b ? __a : __b; })
#endif
#ifndef min3
#define min3(a, b, c) (min(min((a), (b)), (c)))
#endif
#ifndef min4
#define min4(a, b ,c, d) (min(min((a), (b)), min((c), (d))))
#endif

struct nmbuf
{
    void *data;
    size_t *len;
};

struct _nmdev_ring 
{
    struct netmap_ring *ring;
    uint32_t avail;  /* shadow copy of ring->avail (because of
                      * asynchronous operation) */
    uint32_t _avail; /* copy of submitted avail for comparison in
                      * callback */
    uint32_t infly;  /* number of buffers that are used by the user
                      * currently */

    /* copies to reduce number of indirect adressing */
    uint32_t cur;
    uint32_t num_slots;

    int isbusy;     /* bool: backend is currently processing? */
    int chained;    /* bool: another backend notify batched? */
};

struct nmdev
{
    int fd;
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

#define _nmdev_do_notify_xmit(nm)                       \
    do {                                                \
        (nm)->txring.isbusy      = 1;                   \
        (nm)->txring.ring->avail = (nm)->txring.avail;  \
        (nm)->txring.ring->cur   = (nm)->txring.cur;    \
        (nm)->txring._avail      = (nm)->txring.avail;  \
        wmb();                                          \
        (nm)->priv->tx_desc.lock = 1;                   \
        notify_remote_via_evtchn((nm)->priv->tx_desc.evtchn); \
    } while(0)
#define nmdev_notify_xmit(nm)                           \
    do {                                                \
        unsigned int flags;                             \
        local_irq_save(flags);                          \
        if (unlikely(nm->txring.isbusy)) {              \
            (nm)->txring.chained = 1;                   \
            local_irq_restore(flags);                   \
        } else {                                        \
            local_irq_restore(flags);                   \
            _nmdev_do_notify_xmit(nm);                  \
        }                                               \
    } while(0)
/*
    do {                                                \
        if (unlikely(nm->txring.isbusy))                \
            (nm)->txring.chained = 1;                   \
        else                                            \
            _nmdev_do_notify_xmit(nm);                  \
    } while(0)
*/
#define _nmdev_do_notify_recv(nm)                       \
    do {                                                \
        (nm)->rxring.isbusy      = 1;                   \
        (nm)->rxring.ring->avail = (nm)->rxring.avail;  \
        (nm)->txring.ring->cur   = (nm)->txring.cur;    \
        (nm)->rxring._avail      = (nm)->rxring.avail;  \
        wmb();                                          \
        (nm)->priv->rx_desc.lock = 1;                   \
        notify_remote_via_evtchn((nm)->priv->rx_desc.evtchn); \
    } while(0)
#define nmdev_notify_recv(nm)                           \
    do {                                                \
        unsigned int flags;                             \
        local_irq_save(flags);                          \
        if (unlikely(nm->rxring.isbusy)) {              \
            (nm)->rxring.chained = 1;                   \
            local_irq_restore(flags);                   \
        } else {                                        \
            local_irq_restore(flags);                   \
            _nmdev_do_notify_recv(nm);                  \
        }                                               \
    } while(0)
/*
    do {                                                \
        if (unlikely(nm->rxring.isbusy))                \
            (nm)->rxring.chained = 1;                   \
        else                                            \
            _nmdev_do_notify_recv(nm);                  \
    } while(0)
*/
#define nmdev_notify(nm)                                \
    do {                                                \
        nmdev_notify_xmit(nm);                          \
        nmdev_notify_recv(nm);                          \
    } while(0)

#define _nmdev_avail_txbufs(nm) ((nm)->txring.avail - (nm)->txring.infly)
static inline uint32_t nmdev_avail_txbufs(struct nmdev *nm)
{
    uint32_t ret;
    unsigned int flags;

    local_irq_save(flags);
    ret = _nmdev_avail_txbufs(nm);
    local_irq_restore(flags);
    return ret;
}

/*
 * Picks a number of tx buffers from netmap
 * The function returns the actual number of picked slots from netmap buffers
 */
static inline uint32_t nmdev_pick_txbufs(struct nmdev *nm, struct nmbuf txbufs[], uint32_t count)
{
    uint32_t i;
    unsigned int cur;
    unsigned int flags;

    local_irq_save(flags);
    count = min(count, _nmdev_avail_txbufs(nm));

    /* pick available buffers */
    cur = (nm->txring.cur + nm->txring.infly) % nm->txring.num_slots;
    for (i = 0; i < count; i++) {
        txbufs[i].data = NETMAP_BUF(nm->xinfo, cur);
        txbufs[i].len  = (size_t *) &(nm->txring.ring->slot[cur].len);
        cur = NETMAP_RING_NEXT(nm->txring.ring, cur);
    }
    nm->txring.infly += count;
    local_irq_restore(flags);
    return count;
}

/*
 * Puts a tx packet buffers back to netmap
 */
static inline void nmdev_put_txbufs(struct nmdev *nm, uint32_t count)
{
    unsigned int flags;

    ASSERT(count <= nm->txring.infly);

    local_irq_save(flags);
    nm->txring.avail -= count;
    nm->txring.infly -= count;
    nm->txring.cur    = (nm->rxring.cur + count) % nm->rxring.num_slots;;
    local_irq_restore(flags);
}

#define _nmdev_avail_rxbufs(nm) ((nm)->rxring.avail - (nm)->rxring.infly)
static inline uint32_t nmdev_avail_rxbufs(struct nmdev *nm)
{
    uint32_t ret;
    unsigned int flags;

    local_irq_save(flags);
    ret = _nmdev_avail_rxbufs(nm);
    local_irq_restore(flags);
    return ret;
}

static inline uint32_t nmdev_pick_rxbufs(struct nmdev *nm, struct nmbuf rxbufs[], uint32_t count)
{
    uint32_t i;
    unsigned int cur;
    unsigned int flags;

    local_irq_save(flags);
    count = min(count, _nmdev_avail_rxbufs(nm));

    /* pick available buffers */
    cur = (nm->rxring.cur + nm->rxring.infly) % nm->rxring.num_slots;
    for (i = 0; i < count; i++) {
        rxbufs[i].data = NETMAP_BUF(nm->xinfo, cur);
        rxbufs[i].len  = (size_t *) &(nm->rxring.ring->slot[cur].len);
        cur = NETMAP_RING_NEXT(nm->rxring.ring, cur);
    }
    nm->rxring.infly += count;
    local_irq_restore(flags);
    return count;
}

static inline void nmdev_put_rxbufs(struct nmdev *nm, uint32_t count)
{
    unsigned int flags;

    ASSERT(count <= nm->rxring.infly);

    local_irq_save(flags);
    nm->rxring.avail -= count;
    nm->rxring.infly -= count;
    nm->rxring.cur    = (nm->rxring.cur + count) % nm->rxring.num_slots;
    local_irq_restore(flags);
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
    for (i = 0; i < count; i++) {
        *(txbufs[i].len) = pkts[i]->pktlen;
        pkt_copy(pkts[i]->p_obj.data, txbufs[i].data, pkts[i]->pktlen);
    }
    nmdev_put_txbufs(nm, count);
    nmdev_notify_xmit(nm); /* trigger netmap to send */
    pktpool_put_multiple(pkts, count);

    return count;
}

#define nmdev_xmit(nm, pkt) (nmdev_xmit_burst((nm), &(pkt), 1) ? -1 : 0)

static inline uint32_t nmdev_recv_burst(struct nmdev *nm, struct pktbuf **pkts, uint32_t count, struct mempool *pktpool)
{
    struct nmbuf rxbufs[count];
    uint32_t i;

    nmdev_notify_recv(nm); /* trigger netmap to receive */
    count = min3(count, nmdev_avail_rxbufs(nm), pktpool_free_count(pktpool));
    pktpool_pick_multiple(pktpool, pkts, count);
    nmdev_pick_rxbufs(nm, rxbufs, count);
    for (i = 0; i < count; i++) {
        pkts[i]->pktlen = *(rxbufs[i].len);
        pkt_copy(rxbufs[i].data, pkts[i]->p_obj.data, pkts[i]->pktlen);
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
