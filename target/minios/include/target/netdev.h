#ifndef _NETDEV_H_
#define _NETDEV_H_

#include <mini-os/lwip-net.h>

#define target_netif_init \
  netfrontif_init
#define target_netif_poll \
  netfrontif_poll

#endif /* _NETDEV_H_ */
