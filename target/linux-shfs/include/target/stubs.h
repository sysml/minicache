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
