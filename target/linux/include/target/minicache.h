#ifndef _MINICACHE_H_
#define _MINICACHE_H_

#include <target/sys.h>

/*
 * Generic
 */
#define printk(fmt, ...) printf((fmt), ##__VA_ARGS)


/*
 * Networking
 */
#define target_netif_init \
  tapif_init


/*
 * SHUTDOWN
 */
#define TARGET_SHTDN_POWEROFF 0
#define TARGET_SHTDN_REBOOT 1
#define TARGET_SHTDN_SUSPEND 2

#define target_suspend() \
  do {} while(0)

#define target_halt() \
  do {} while(0)

#define target_reboot() \
  do {} while(0)

#endif /* _MINICACHE_H_ */
