/*
 * Simple ring implementation for storing
 * object references
 * This implementation is a modified port of FreeBSD's
 * buf_ring implementation to MiniOS. Also, this
 * implementation is not SMP-safe.
 *
 * Copyright(C) 2013 NEC Laboratories Europe. All rights reserved.
 */
/*
 * Derived from FreeBSD's buf_ring.h
 *
 **************************************************************************
 *
 * Copyright (c) 2007,2008 Kip Macy kmacy@freebsd.org
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. The name of Kip Macy nor the names of other
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 ***************************************************************************/
#include <mini-os/os.h>
#include <mini-os/types.h>
#include <mini-os/xmalloc.h>
#include <kernel.h>
#include <errno.h>

#include "ring.h"

#define CACHELINE_SIZE 64

/* checks if a number is a power of two. Copied from BNX2X driver (Linux) */
#ifndef POWER_OF_2
  #define POWER_OF_2(x)   ((0 != (x)) && (0 == ((x) & ((x)-1))))
#endif

/* Return size, increased to alignment with align. Copied from xmalloc.c */
static inline size_t align_up(size_t size, size_t align)
{
  return (size + align - 1) & ~(align - 1);
}

struct ring *alloc_ring(uint32_t size)
{
  struct ring *r;
  size_t h_size = align_up(sizeof(struct ring), CACHELINE_SIZE);

  ASSERT(size > 0 && POWER_OF_2(size));

  r = _xmalloc(h_size + (sizeof(void *) * size), PAGE_SIZE);
  if (!r) {
	errno = ENOMEM;
	return NULL;
  }
  r->size = size;
  r->mask = size - 1;
  r->enq_idx = 0;
  r->deq_idx = 0;
  r->ring = (void **) ((uintptr_t) r + h_size);
  return r;
}

void free_ring(struct ring *r)
{
  free(r);
}
