#ifndef _SYS_H_
#define _SYS_H_

#include <mini-os/os.h>
#include <mini-os/types.h>
#include <mini-os/xmalloc.h>
#include <mini-os/lib.h>
#include <mini-os/kernel.h>

#define target_malloc(align, size) \
  ((void *) _xmalloc((size), (align)))
#define target_free(ptr) \
  xfree(ptr)

/* semaphores */
#include <mini-os/semaphore.h>
typedef struct semaphore sem_t;

/* shutdown */
#include <mini-os/shutdown.h>

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

#define target_crash() \
  kernel_shutdown(SHUTDOWN_crash)

#define target_init() \
	do {} while(0)
#define target_exit() \
	do {} while(0)

#endif /* _SYS_H_ */
