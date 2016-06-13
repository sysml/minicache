#ifndef SHFS_STUBS_H
#define SHFS_STUBS_H

typedef int sem_t;

struct blkdev;
static inline void blkdev_poll_req(struct blkdev *bd)
{ BUG(); }

#define blkdev_async_io_submit(bd) do {} while(0)
#define blkdev_async_io_wait_slot(bd) do {} while(0)


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

static inline struct blkdev *open_blkdev(blkdev_id_t id, int mode)
{ BUG(); }

#define blkdev_sync_read(bd, start, len, buffer) 0;
static inline void close_blkdev(struct blkdev *bd)
{ BUG(); }
#define ENOTSUP ENOTSUPP

#define init_SEMAPHORE(s, v)
static inline int sem_stub(uint64_t s) { return 1; }
#define up(s) sem_stub((uint64_t) s)
#define down(s) sem_stub((uint64_t) s)
#define trydown(s) sem_stub((uint64_t) s)

#define alloc_mempool(a, b, c, d, e, f, g, h) NULL
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

static inline int blkdev_async_io(struct blkdev *bd, sector_t start, sector_t len,
                                  int write, void *buffer, blkdev_aiocb_t *cb, void *cb_argp)
{
	BUG();
	return 0;
}

/* temporary stubs */
struct htable;
static inline void free_htable(struct htable *ht) { BUG(); }


/* static inline */
/* struct blkdev *shfs_checkopen_blkdev(blkdev_id_t bd_id, */
/* 				     void *chk0, int mode) */
/* { */
/* 	BUG(); */
/* } */
#endif
