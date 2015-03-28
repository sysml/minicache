#ifndef _NETDEV_H_
#define _NETDEV_H_

#ifdef CONFIG_PCAPIF
#include <netif/pcapif.h>

#define target_netif_init \
  pcapif_init
#else
#include <netif/tapif.h>

#define target_netif_init \
  tapif_init
#endif

#endif
