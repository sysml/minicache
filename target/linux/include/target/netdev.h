#ifndef _NETDEV_H_
#define _NETDEV_H_

#if defined CONFIG_OSVNET
#include <netif/osv-net.h>
#define target_netif_init \
  osvnetif_init
#define target_netif_poll \
  osvnetif_poll
#define CONFIG_LWIP_IPDEV

#elif defined CONFIG_PCAPIF
#include <netif/pcapif.h>
#define target_netif_init \
  pcapif_init

#elif defined CONFIG_NETMAP
#include <netif/netmapif.h>
#define target_netif_init \
  netmapif_init
#define target_netif_poll \
  netmapif_poll

#else
#include <netif/tapif.h>
#define target_netif_init \
  tapif_init
#define target_netif_poll \
  tapif_poll

#endif

#endif
