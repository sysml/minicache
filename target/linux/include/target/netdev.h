#ifndef _NETDEV_H_
#define _NETDEV_H_

#include <netif/tapif.h>
//#include <netif/tunif.h>
//#include <netif/unixif.h>

#define target_netif_init \
  tapif_init

//tunif_init
//unixif_init

#endif
