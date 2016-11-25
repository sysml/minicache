#ifndef _NETDEV_H_
#define _NETDEV_H_

#include <mini-os/lwip-net.h>

#ifdef CONFIG_NETMAPFRONT
#include <mini-os/netmapfront.h>

#define target_netif_init \
  netmapfrontif_init
#define target_netif_poll \
  netmapfrontif_poll

#ifdef CONFIG_SELECT_POLL
#define CAN_POLL_NETDEV
#define target_netif_fd \
  netmapfrontif_fd
#endif /* CONFIG_SELECT_POLL */

#else

#define target_netif_init \
  netfrontif_init
#define target_netif_poll \
  netfrontif_poll

#ifdef CONFIG_SELECT_POLL
#define CAN_POLL_NETDEV
#define target_netif_fd \
  netfrontif_fd
#endif /* CONFIG_SELECT_POLL */

#endif /* CONFIG_NETMAPFRONT */
#endif /* _NETDEV_H_ */
