#ifndef _NETDEV_H_
#define _NETDEV_H_

#include <netif/tapif.h>

#define target_netif_init \
  tapif_init

#endif
