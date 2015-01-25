#ifndef _SYS_H_
#define _SYS_H_

#include <mini-os/os.h>
#include <mini-os/types.h>
#include <mini-os/xmalloc.h>
#include <mini-os/lib.h>
#include <mini-os/kernel.h>

#define aligned_alloc(align, size) \
        ((void *) _xmalloc((size), (align)))

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

#endif /* _SYS_H_ */
