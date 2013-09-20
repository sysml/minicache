#include <limits.h>
#include <errno.h>
#include <semaphore.h>
#include <sys/time.h>
#include <mini-os/xmalloc.h>

#include "netdev.h"

static void _netdev_rx(unsigned char *data, int len) {
  /* packet receive callback */
  /* TODO: How to figure out from which dev the data was received? */
  ;
}

struct netdev *open_netdev(unsigned int vif_id)
{
  unsigned int i;
  struct netdev *nd;
  char path[256];
  char *xb_tmpmac;
  char *xb_errmsg;
  unsigned char mac[6];
  char strmac[sizeof(mac) * 3];

  nd = xmalloc(struct netdev);
  if (!nd) {
	errno = ENOMEM;
	goto err;
  }

  /* retrieve interface mac address */
  nd->mac.addr[0] = 0xAA;
  nd->mac.addr[1] = 0xBB;
  nd->mac.addr[2] = 0xCC;
  nd->mac.addr[3] = 0xDD;
  nd->mac.addr[4] = 0xEE;
  nd->mac.addr[5] = 0xFF;
 
#ifdef CONFIG_NETMAP_XENBUS
  snprintf(path, sizeof(path), "/local/domain/%u/device/vale/%u/mac", xenbus_get_self_id(), vif_id);
#else
  snprintf(path, sizeof(path), "/local/domain/%u/device/vif/%u/mac", xenbus_get_self_id(), vif_id);
#endif
  xb_errmsg = xenbus_read(XBT_NIL, path, &xb_tmpmac);
  if (xb_errmsg) {
	free(xb_errmsg);
	errno = ENODEV;
    goto err_free_nd;
  }
  if (xb_tmpmac) {
	sscanf(xb_tmpmac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
		   &(nd->mac.addr[0]), &(nd->mac.addr[1]), &(nd->mac.addr[2]),
		   &(nd->mac.addr[3]), &(nd->mac.addr[4]), &(nd->mac.addr[5]));
	free(xb_tmpmac);
  }

  /* open netfront device */
  for (i = 0; i < 6; i++)
	mac[i] = nd->mac.addr[i];
  snprintf(strmac, sizeof(strmac), "%hhx:%hhx:hhx:%hhx:%hhx:%hhx", nd->mac.addr[0], nd->mac.addr[1],
		   nd->mac.addr[2], nd->mac.addr[3], nd->mac.addr[4], nd->mac.addr[5]);
  nd->dev = init_netfront(NULL, _netdev_rx, mac, NULL, strmac);
  if (!nd->dev) {
	errno = ENODEV;
	goto err_free_nd;
  }

  return nd;

 err_free_nd:
  free(nd);
 err:
  return NULL;
}

void close_netdev(struct netdev *nd)
{
  if (!nd)
	return;

  shutdown_netfront(nd->dev);
  free(nd);
}
