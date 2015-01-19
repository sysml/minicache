#ifndef _SYS_H_
#define _SYS_H_

#include <stdlib.h>
#include <inttypes.h>
#include <limits.h>
#include <semaphore.h>
#include <assert.h>

#define PAGE_SHIFT 12
#define PAGE_SIZE (1<<(PAGE_SHIFT))

#define local_irq_save(flags) \
  (flags = 0)
#define local_irq_restore(flags) \
  (flags = 1)

#define ASSERT(x) assert((x))
#define BUG_ON(x) assert(!((x)))

#endif /* _SYS_H_ */
