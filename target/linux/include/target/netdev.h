#ifndef _NETDEV_H_
#define _NETDEV_H_

#if defined CONFIG_OSVNET
#include <netif/osv-net.h>
#define target_netif_init \
  osvnetif_init
#define target_netif_poll \
  osvnetif_poll

#elif defined CONFIG_PCAPIF
#include <netif/pcapif.h>
#define target_netif_init \
  pcapif_init

#else
#include <netif/tapif.h>
#define target_netif_init \
  tapif_init

#endif

#endif
