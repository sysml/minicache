/*
 * SHFS stubs disabling unneeded minicache functionality
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
 */

#ifndef SHFS_STUBS_H
#define SHFS_STUBS_H

#include <linux/bug.h>

typedef int sem_t;


struct mempool {
	int a;
};
static inline struct mempool_obj *mempool_pick(struct mempool *p)
{ BUG(); }

struct mempool_obj {
	int *data;
};
static inline void mempool_put(struct mempool_obj *obj)
{ BUG(); }

extern int shfs_errno;
#define errno shfs_errno

#define ENOTSUP ENOTSUPP

#define init_SEMAPHORE(s, v)
static inline int sem_stub(uint64_t s) { return 1; }
#define up(s) sem_stub((uint64_t) s)
#define down(s) sem_stub((uint64_t) s)
#define trydown(s) sem_stub((uint64_t) s)

#define alloc_mempool(a, b, c, d, e, f, g, h) ((void *) 0xdeadbeaf)
#define shfs_alloc_cache() 1
#define shfs_free_cache()
#define free_mempool(a)
#define shfs_flush_cache()

static inline int mempool_free_count(struct mempool *a)
{
	BUG();
	return 0;
}

static inline int shfs_cache_ref_count(void)
{
	BUG();
	return 0;
}

/* temporary stubs */
 
#define UINT64_MAX ((uint64_t) (-1))

#define __BYTE_ORDER __LITTLE_ENDIAN
#ifndef __BIG_ENDIAN
#define __BIG_ENDIAN 0
#endif

/* static inline */
/* struct blkdev *shfs_checkopen_blkdev(blkdev_id_t bd_id, */
/* 				     void *chk0, int mode) */
/* { */
/* 	BUG(); */
/* } */
#endif
