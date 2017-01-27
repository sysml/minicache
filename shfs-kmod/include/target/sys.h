#ifndef _SYS_H_
#define _SYS_H_

#include <linux/limits.h>
#include <linux/semaphore.h>
#include <linux/slab.h>


#define target_malloc(align, size) \
  kmalloc(size, GFP_KERNEL)
#define target_free(ptr) \
  kfree(ptr)

#define ASSERT(x) BUG_ON(!(x))

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

/* #define init_SEMAPHORE(s, v) sem_init((s), 0, (v)) /\* negative semaphores? *\/ */
/* #define up(s) (sem_post((s)) ? 0 : 1) */
/* #define down(s) (sem_wait((s)) ? 0 : 1) */
/* #define trydown(s) (sem_trywait((s)) ? 0 : 1) */




#define target_now_ns() ({ \
	uint64_t r;						\
	struct timeval now;					\
	gettimeofday(&now, NULL);				\
	r = now.tv_usec * 1000 + now.tv_sec * 1000000000l;	\
	r; })

#define NSEC_TO_MSEC(ns) ((ns) / 1000000l)

/* env init/exit */
#ifdef CONFIG_PTH_THREADS
#define target_init() \
	pth_init()
#define target_exit() \
	pth_exit(NULL)
#else
#define target_init() \
	do {} while (0)
#define target_exit() \
	do {} while (0)
#endif


#endif /* _SYS_H_ */
