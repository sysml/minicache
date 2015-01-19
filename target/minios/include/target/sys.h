#ifndef _SYS_H_
#define _SYS_H_

#include <mini-os/os.h>
#include <mini-os/types.h>
#include <mini-os/xmalloc.h>
#include <mini-os/lib.h>
#include <mini-os/kernel.h>
#include <mini-os/semaphore.h>

#define aligned_alloc(align, size) \
        ((void *) _xmalloc((size), (align)))

typedef struct semaphore sem_t;

#endif /* _SYS_H_ */
