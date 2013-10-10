/*
 * (C) 2013 NEC Laboratories Europe Ltd.
 *          Simon Kuenzer
 * Simple netmap driver frontend
 */

#include <limits.h>
#include <errno.h>
#include <fcntl.h>    /* open */
#include <unistd.h>   /* close */
#include <sys/mman.h> /* mmap */
#include <mini-os/xmalloc.h>

#include "nmdev.h"

static int _nmdev_xmit_cb(struct netmap_ring *ring, void *argp)
{
    struct nmdev *nm = argp;
    uint32_t diff;
    
    diff = nm->txring.ring->avail - nm->txring._avail;
    nm->txring.avail += diff;
    if (nm->txring.chained) {      /* if there was another try to notify in the
                                    * meantime, directly initiate another
                                    * round (isbusy is kept, chained flag is
                                    * reset) */
        nm->txring.chained = 0;
        _nmdev_do_notify_xmit(nm); /* trigger sent out again */
        return 0;
    }
    nm->txring.isbusy = 0;
    return 0;
}

static int _nmdev_recv_cb(struct netmap_ring *ring, void *argp)
{
    struct nmdev *nm = argp;
    uint32_t diff;

    diff = nm->rxring.ring->avail - nm->rxring._avail;
    nm->rxring.avail += diff;
    if (nm->rxring.chained) {
        nm->rxring.chained = 0;
        _nmdev_do_notify_recv(nm);
        return 0;
    }
    nm->rxring.isbusy = 0;
    return 0;
}


struct nmdev *open_nmdev(unsigned int vif_id)
{
    struct nmdev *nm;
    char path[256];
    char *xb_tmpmac;
    char *xb_errmsg;
    void *mmap_ptr;
    unsigned int cur;
    uint32_t i;
    int err;

    nm = xmalloc(struct nmdev);
    if (!nm) {
        errno = ENOMEM;
        goto err;
    }

    /* Find device in xenstore and figure out its MAC */
    snprintf(path, sizeof(path), "/local/domain/%u/device/vale/%u/mac", xenbus_get_self_id(), vif_id);
    xb_errmsg = xenbus_read(XBT_NIL, path, &xb_tmpmac);
    if (xb_errmsg || (!xb_tmpmac)) {
        if (xb_errmsg)
            free(xb_errmsg);
        errno = ENODEV;
        goto err_free_nm;
    }
    if (xb_tmpmac) {
        sscanf(xb_tmpmac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &(nm->mac.addr[0]), &(nm->mac.addr[1]), &(nm->mac.addr[2]),
               &(nm->mac.addr[3]), &(nm->mac.addr[4]), &(nm->mac.addr[5]));
        free(xb_tmpmac); 
    }

    /* open netmap device and map memory region */
    /*
     * FIXME: Select device specified by vif_id
     *        Here, just the first available interface is used
     */
    nm->fd = open("/dev/netmap", O_RDWR);
    if (nm->fd < 0) {
        errno = ENXIO;
        goto err_free_nm;
    }
    mmap_ptr = mmap(0, 0, PROT_WRITE | PROT_READ, MAP_SHARED, nm->fd, 0);
    if (mmap_ptr == MAP_FAILED) {
        errno = ENOMEM;
        goto err_close_fd;
    }
    nm->priv = (struct netmap_priv_d *) mmap_ptr;
    nm->nifp = (struct netmap_if *) mmap_ptr;
    nm->xinfo = &nm->priv->tx_desc;

    /* Initialize netmap ring management */
    nm->txring.ring      = NETMAP_TXRING(nm->priv, 0);
    nm->txring.avail     = nm->txring.ring->avail;
    nm->txring.cur       = nm->txring.ring->cur;
    nm->txring.num_slots = nm->txring.ring->num_slots;
    nm->txring.infly     = 0;

    nm->rxring.ring      = NETMAP_RXRING(nm->priv, 0);
    nm->rxring.avail     = 0; /* workaround: netmap is returning an
                               * unitialized value here until it gets
                               * polled for the first time */
    nm->rxring.cur       = nm->rxring.ring->cur;
    nm->rxring.num_slots = nm->rxring.ring->num_slots;
    nm->rxring.infly     = 0;

    ASSERT(nm->txring.num_slots == nm->txring.avail + 1);
    ASSERT(nm->rxring.avail == 0);

    /* Reset flags on netmap slots */
    cur = nm->txring.ring->cur;
    for (i = 0; i < nm->txring.ring->num_slots; i++) {
        nm->txring.ring->slot[cur].flags = 0;
        cur = NETMAP_RING_NEXT(nm->txring.ring, cur);
    }
    cur = nm->rxring.ring->cur;
    for (i = 0; i < nm->rxring.ring->num_slots; i++) {
        nm->rxring.ring->slot[cur].flags = 0;
        cur = NETMAP_RING_NEXT(nm->rxring.ring, cur);
    }

    /* Register callback for asynchrous netmap notify */
    err = netmap_regup(nm->priv, TX_CH, (RING_UPDATE_T) _nmdev_xmit_cb, nm);
    if (err) {
        errno = -err;
        goto err_munmap;
    }
    err = netmap_regup(nm->priv, RX_CH, (RING_UPDATE_T) _nmdev_recv_cb, nm);
    if (err) {
        errno = -err;
        goto err_munmap;
    }

    return nm;

err_munmap:
    munmap(mmap_ptr, 0);
err_close_fd:
    close(nm->fd);
err_free_nm:
    free(nm);
err:
    return NULL;
}

void close_nmdev(struct nmdev *nm)
{
    if (!nm)
        return;

    ASSERT(nm->txring.infly == 0);
    ASSERT(nm->rxring.infly == 0);

    munmap(nm->priv, 0);
    close(nm->fd);
    free(nm);
}
