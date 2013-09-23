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

#define NM_BUFLEN 2048 /* TODO: Read this value from xenstore */

struct nmdev *open_nmdev(unsigned int vif_id)
{
    struct nmdev *nm;
    char path[256];
    char *xb_tmpmac;
    char *xb_errmsg;
    
    nm = xmalloc(struct nmdev);
    if (!nm) {
        errno = ENOMEM;
        goto err;
    }

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
     */
    nm->fd = open("/dev/netmap", O_RDWR);
    if (nm->fd < 0) {
        errno = ENXIO;
        goto err_free_nm;
    }
    nm->priv = (struct netmap_priv_d *) mmap(0, 0, PROT_WRITE | PROT_READ, MAP_SHARED, nm->fd, 0);
    if (nm->priv == MAP_FAILED) {
        errno = ENOMEM;
        goto err_close_fd;
    }
    nm->nifp = (struct netmap_if *) nm->priv;
    nm->txring = NETMAP_TXRING(nm->priv, 0);
    nm->rxring = NETMAP_RXRING(nm->priv, 0);
    nm->pfd.fd = nm->fd;
    
    return nm;

//err_munmap_priv:
//    munmap(nm->priv, 0);
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
    
    munmap(nm->priv, 0);
    close(nm->fd);
    free(nm);
}
