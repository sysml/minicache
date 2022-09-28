/*
 * Platform wrapper for MiniOS
 *
 * Authors: Simon Kuenzer <simon.kuenzer@neclab.eu>
 *
 *
 * Copyright (c) 2013-2017, NEC Europe Ltd., NEC Corporation All rights reserved.
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
 */
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

/*
#ifdef CONFIG_ARM
#define target_now_ns() ({ \
	uint64_t r;						\
	struct timeval now;					\
	gettimeofday(&now, NULL);				\
	r = now.tv_usec * 1000 + now.tv_sec * 1000000000l;	\
	r; })
#else
*/
#define target_now_ns() (NOW())
/*
#endif
*/

#endif /* _SYS_H_ */
