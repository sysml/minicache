#ifndef _MINICACHE_H_
#define _MINICACHE_H_

#include <mini-os/os.h>
#include <mini-os/types.h>
#include <mini-os/xmalloc.h>
#include <kernel.h>

/*
 * Generic
 */
//#define printk printf


/*
 * Networking
 */
#define target_netif_init \
  netfrontif_init


/*
 * SHUTDOWN
 */
#include <shutdown.h>

#define TARGET_SHTDN_POWEROFF \
  SHUTDOWN_poweroff
#define TARGET_SHTDN_REBOOT \
  SHUTDOWN_reboot
#define TARGET_SHTDN_SUSPEND \
  SHUTDOWN_suspend

#define target_suspend() \
  kernel_suspend()

#define target_halt() \
  kernel_shutdown(SHUTDOWN_poweroff)

#define target_reboot() \
  kernel_shutdown(SHUTDOWN_reboot)

#endif /* _MINICACHE_H_ */
