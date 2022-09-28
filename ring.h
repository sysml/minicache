/*
 * Simple ring implementation to handle object references.
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
/*
 * Parts of this code is derived/copied from FreeBSD's buf_ring.h:
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
 */
/* Note: This implementation is thread-safe but not SMP-safe. */

#ifndef _RING_H_
#define _RING_H_

#include <target/sys.h>

#include <stdint.h>
#include <errno.h>

struct ring {
    volatile uint32_t enq_idx;
    volatile uint32_t deq_idx;
    uint32_t size;
    uint32_t mask;
    void **ring;
};

/* Note: size has to be a power of to. (size - 1) slots are available in the ring */
struct ring *alloc_ring(uint32_t size);
void free_ring(struct ring *r);

#define ring_full(r) ((((r)->enq_idx + 1) & (r)->mask) == (r)->deq_idx)
#define ring_empty(r) ((r)->enq_idx == (r)->deq_idx)
/* number of used slots */
#define ring_count(r) (((r)->size + (r)->enq_idx - (r)->deq_idx) & (r)->mask)
/* number of available slots */
#define ring_avail(r) (((r)->mask + (r)->deq_idx - (r)->enq_idx) & (r)->mask)

/*
 * Multi-producer-safe enqueue
 * Returns 0 on success, -1 on errors (inspect errno for reason)
 */
static inline int ring_enqueue(struct ring *r, void *element)
{
    uint32_t enq_idx;
    unsigned long flags;

    local_irq_save(flags);
    enq_idx = r->enq_idx;

    if (((enq_idx + 1) & r->mask) == r->deq_idx) {
        local_irq_restore(flags);
        errno = ENOBUFS;
        return -1;
    }
    r->ring[enq_idx] = element;
    r->enq_idx = (enq_idx + 1) & r->mask;
    local_irq_restore(flags);
    return 0;
}

/*
 * Returns 0 on success, -1 on errors (inspect errno for reason)
 */
static inline int ring_enqueue_multiple(struct ring *r, void *elements[], uint32_t count)
{
    uint32_t i;
    uint32_t enq_idx;
    unsigned long flags;

    local_irq_save(flags);
    enq_idx = r->enq_idx;

    if (((r->size - 1) - ring_count(r)) < count) {
        local_irq_restore(flags);
        errno = ENOBUFS;
        return -1;
    }

    for (i=0; i<count; i++) {
        r->ring[enq_idx] = elements[i];
        enq_idx = (enq_idx + 1) & r->mask;
    }
    r->enq_idx = enq_idx;
    local_irq_restore(flags);
    return 0;
}

/*
 * Returns the number of successfully dequeued elements
 */
static inline uint32_t ring_try_enqueue_multiple(struct ring *r, void *elements[], uint32_t count)
{
    uint32_t i = 0;
    int ret = 0;

    while (!ret || i < count)
        ret = ring_enqueue(r, elements[i++]);

    if (!ret)
        return i;
    return (i - 1);
}

/*
 * Multi-consumer-safe dequeue
 * Returns NULL on errors (inspect errno for reason)
 */
static inline void *ring_dequeue(struct ring *r)
{
    uint32_t deq_idx;
    unsigned long flags;
    void *e;

    local_irq_save(flags);
    deq_idx = r->deq_idx;

    if (deq_idx == r->enq_idx) {
        local_irq_restore(flags);
        errno = ENOBUFS;
        return NULL;
    }
    e = r->ring[deq_idx];
    r->deq_idx = (deq_idx + 1) & r->mask;
    local_irq_restore(flags);
    return e;
}

/*
 * Returns 0 on success, -1 on errors (inspect errno for reason)
 */
static inline int ring_dequeue_multiple(struct ring *r, void *elements[], uint32_t count)
{
    uint32_t i;
    uint32_t deq_idx;
    unsigned long flags;

    local_irq_save(flags);
    deq_idx = r->deq_idx;

    if ((ring_count(r)) < count) {
        local_irq_restore(flags);
        errno = ENOBUFS;
        return -1;
    }

    for (i=0; i<count; i++) {
        elements[i] = r->ring[deq_idx];
        deq_idx = (deq_idx + 1) & r->mask;
    }
    r->deq_idx = deq_idx;
    local_irq_restore(flags);
    return 0;
}

/*
 * Returns the number of successfully dequeued elements
 */
static inline uint32_t ring_try_dequeue_multiple(struct ring *r, void *elements[], uint32_t count)
{
    uint32_t i = 0;
    int ret = 0;
    void *e;

    while (!ret || i < count) {
        e = ring_dequeue(r);
        if (!e)
            return i;
        elements[i++] = e;
    }

    return i;
}

#endif /* _RING_H_ */
