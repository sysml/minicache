/*
 * Minicache system definitions required to shfs
 *
 * Authors: Yuri Volchkov <iurii.volchkov@neclab.eu>
 *
 *
 * Copyright (c) 2013-2017, NEC Europe Ltd., NEC Corporation All rights reserved
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, or the BSD license below:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * THIS HEADER MAY NOT BE EXTRACTED OR MODIFIED IN ANY WAY.
 */

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
