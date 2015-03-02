#ifndef _SYS_H_
#define _SYS_H_

/* #include <stdio.h> */
#include <stdlib.h>
#include <inttypes.h>
#include <limits.h>
#include <semaphore.h>
#include <assert.h>

#define PAGE_SHIFT 12
#define PAGE_SIZE (1<<(PAGE_SHIFT))

#define target_malloc(align, size) \
  malloc(size)
#define target_free(ptr) \
  free(ptr)

#define local_irq_save(flags) \
  (flags = 0)
#define local_irq_restore(flags) \
  (flags = 1)

#define ASSERT(x) assert((x))
#define BUG_ON(x) assert(!((x)))
#define printk(...) printf(__VA_ARGS__)

/* shutdown */
#define TARGET_SHTDN_POWEROFF 0
#define TARGET_SHTDN_REBOOT 1
#define TARGET_SHTDN_SUSPEND 2

#define target_suspend() \
  do { \
    printk("WARNING: 'suspend' is not supported by platform; ignore\n"); \
  } while(0)

#define target_halt() \
  exit(0)

#define target_reboot() \
  do { \
    printk("WARNING: 'reboot' is not supported by platform; use 'halt'\n"); \
    target_halt(); \
  } while(0)

void app_shutdown(unsigned reason);

/* scheduling */
#define msleep(ms) usleep((((ms)) * 1000l))

/* #include <sched.h>
 * #define schedule() sched_yield() */

/* semaphore */
#define init_SEMAPHORE(s, v) sem_init((s), 0, (v)) /* negative semaphres? */
#define up(s) sem_post((s))
#define down(s) sem_wait((s))
#define trydown(s) down((s)) /* FIXME */

#define schedule() \
  do {} while(0)

#endif /* _SYS_H_ */
