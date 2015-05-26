#ifndef _SYS_H_
#define _SYS_H_

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <limits.h>
#include <semaphore.h>
#include <assert.h>
#include <sys/time.h>

#ifndef PAGE_SHIFT
#define PAGE_SHIFT 12
#endif
#ifndef PAGE_SIZE
#define PAGE_SIZE (1<<(PAGE_SHIFT))
#endif

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

#define target_crash() \
  exit(1)

void app_shutdown(unsigned reason);

/* scheduling */
#define msleep(ms) usleep((((ms)) * 1000l))

#ifdef CONFIG_PTH_THREADS
#include <pth.h>

#define thread pth
#define schedule() \
	pth_yield(NULL)
#define create_thread(name, func, argp) \
	pth_spawn(PTH_ATTR_DEFAULT, (void * (*)(void *)) (func), (argp))
#define exit_thread() \
	pth_exit(NULL)
#else
#define thread (void *)
#define schedule() \
	do {} while (0)
#define create_thread(name, func, argp) \
	do {} while (0)
#define exit_thread() \
	do {} while (0)
#endif

/* semaphore */
#define init_SEMAPHORE(s, v) sem_init((s), 0, (v)) /* negative semaphres? */
#define up(s) (sem_post((s)) == 0 ? 1 : 0)
#define down(s) (sem_wait((s)) == 0 ? 1 : 0)
#define trydown(s) (sem_trywait((s)) == 0 ? 1 : 0)

#define target_now_ns() ({ \
	uint64_t r;						\
	struct timeval now;					\
	gettimeofday(&now, NULL);				\
	r = now.tv_usec * 1000 + now.tv_sec * 1000000000l;	\
	r; })

#define NSEC_TO_MSEC(ns) ((ns) / 1000000l)

/* env init/exit */
#define target_init() \
	pth_init()
#define target_exit() \
	pth_exit(NULL)

#endif /* _SYS_H_ */
