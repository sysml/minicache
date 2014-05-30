#ifndef _BLKDEV_H_
#define _BLKDEV_H_

#include <mini-os/blkfront.h>
#include <mempool.h>
#include <fcntl.h>
#include <semaphore.h>

#define MAX_REQUESTS ((__RING_SIZE((struct blkif_sring *)0, PAGE_SIZE)) - 1)
#define MAX_DISKSIZE (1ll << 40) /* 1 TB */

typedef uint64_t sector_t;
typedef void (blkdev_aiocb_t)(int ret, void *argp);

struct blkdev {
  struct blkfront_dev *dev;
  struct blkfront_info info;
  struct mempool *reqpool;
  char nname[64];
  unsigned int vbd_id;

  int exclusive;
  unsigned int refcount;
  struct blkdev *_next;
  struct blkdev *_prev;
};

struct _blkdev_req {
  struct mempool_obj *p_obj; /* reference to dependent memory pool object */
  struct blkdev *bd;
  struct blkfront_aiocb aiocb;
  sector_t sector;
  sector_t nb_sectors;
  int write;
  blkdev_aiocb_t *cb;
  void *cb_argp;
};

unsigned int detect_blkdevs(unsigned int vbd_ids[], unsigned int max_nb);
struct blkdev *open_blkdev(unsigned int vbd_id, int mode);
void close_blkdev(struct blkdev *bd);


/**
 * Retrieve device information
 */
static inline sector_t blkdev_sectors(struct blkdev *bd)
{
  /* WORKAROUND: blkfront cannot handle > 1TB -> limit the disk size */
  if (((sector_t) bd->info.sectors * (sector_t) bd->info.sector_size) > MAX_DISKSIZE)
	return (MAX_DISKSIZE / (sector_t) bd->info.sector_size);
  return (sector_t) bd->info.sectors;
}
#define blkdev_ssize(bd) ((uint32_t) (bd)->info.sector_size)
#define blkdev_size(bd) (blkdev_sectors((bd)) * (sector_t) blkdev_ssize((bd)))
#define blkdev_avail_req(bd) mempool_free_count((bd)->reqpool)


/**
 * Async I/O
 *
 * Note: target buffer has to be aligned to device sector size
 */
void _blkdev_async_io_cb(struct blkfront_aiocb *aiocb, int ret);

static inline int blkdev_async_io_nocheck(struct blkdev *bd, sector_t start, sector_t len,
                                          int write, void *buffer, blkdev_aiocb_t *cb, void *cb_argp)
{
  struct mempool_obj *robj;
  struct _blkdev_req *req;

  robj = mempool_pick(bd->reqpool);
  if (unlikely(!robj))
	return -EAGAIN; /* too many requests on queue */

  req = robj->data;
  req->p_obj = robj;

  req->aiocb.data = NULL;
  req->aiocb.aio_dev = bd->dev;
  req->aiocb.aio_buf = buffer;
  req->aiocb.aio_offset = (off_t) (start * blkdev_ssize(bd));
  req->aiocb.aio_nbytes = len * blkdev_ssize(bd);
  req->aiocb.aio_cb = _blkdev_async_io_cb;
  req->bd = bd;
  req->sector = start;
  req->nb_sectors = len;
  req->write = write;
  req->cb = cb;
  req->cb_argp = cb_argp;

  blkfront_aio(&(req->aiocb), write);
  return 0;
}
#define blkdev_async_write_nocheck(bd, start, len, buffer, cb, cb_argp) \
	blkdev_async_io_nocheck((bd), (start), (len), 1, (buffer), (cb), (cb_argp))
#define blkdev_async_read_nocheck(bd, start, len, buffer, cb, cb_argp) \
	blkdev_async_io_nocheck((bd), (start), (len), 0, (buffer), (cb), (cb_argp))

static inline int blkdev_async_io(struct blkdev *bd, sector_t start, sector_t len,
                                  int write, void *buffer, blkdev_aiocb_t *cb, void *cb_argp)
{
	if (unlikely(write && !(bd->info.mode & (O_WRONLY | O_RDWR)))) {
		/* write access on non-writable device or read access on non-readable device */
		return -EACCES;
	}

	if (unlikely((len * blkdev_ssize(bd)) / PAGE_SIZE > BLKIF_MAX_SEGMENTS_PER_REQUEST)) {
		/* request too big -> blockfront cannot handle it with a single request */
		return -ENXIO;
	}

	if (unlikely(((uint64_t) buffer) & ((uint64_t) blkdev_ssize(bd) - 1))) {
		/* buffer is not aligned to device sector size */
		return -EINVAL;
	}

	return blkdev_async_io_nocheck(bd, start, len, write, buffer, cb, cb_argp);
}
#define blkdev_async_write(bd, start, len, buffer, cb, cb_argp)	  \
	blkdev_async_io((bd), (start), (len), 1, (buffer), (cb), (cb_argp))
#define blkdev_async_read(bd, start, len, buffer, cb, cb_argp)	  \
	blkdev_async_io((bd), (start), (len), 0, (buffer), (cb), (cb_argp))

#define blkdev_poll_req(bd) blkfront_aio_poll((bd)->dev);

/**
 * Sync I/O
 */
void _blkdev_sync_io_cb(int ret, void *argp);

struct _blkdev_sync_io_sync {
	struct semaphore sem;
	int ret;
};

static inline int blkdev_sync_io_nocheck(struct blkdev *bd, sector_t start, sector_t len,
                                             int write, void *target)
{
	struct _blkdev_sync_io_sync iosync;
	int ret;

	init_SEMAPHORE(&iosync.sem, 0);
	ret = blkdev_async_io_nocheck(bd, start, len, write, target,
	                              _blkdev_sync_io_cb, &iosync);
	while (ret == -EAGAIN) {
		/* try again, queue was full */
		blkdev_poll_req(bd);
		schedule();
		ret = blkdev_async_io_nocheck(bd, start, len, write, target,
		                              _blkdev_sync_io_cb, &iosync);
	}
	if (ret < 0)
		return ret;

	/* wait for I/O completion */
	blkdev_poll_req(bd);
	while (trydown(&iosync.sem) == 0) {
		schedule(); /* yield CPU */
		blkdev_poll_req(bd);
	}

	return iosync.ret;
}
#define blkdev_sync_write_nocheck(bd, start, len, buffer)	  \
	blkdev_sync_io_nocheck((bd), (start), (len), 1, (buffer))
#define blkdev_sync_read_nocheck(bd, start, len, buffer)	  \
	blkdev_sync_io_nocheck((bd), (start), (len), 0, (buffer))

static inline int blkdev_sync_io(struct blkdev *bd, sector_t start, sector_t len,
                                 int write, void *target)
{
	struct _blkdev_sync_io_sync iosync;
	int ret;

	init_SEMAPHORE(&iosync.sem, 0);
	ret = blkdev_async_io(bd, start, len, write, target,
	                      _blkdev_sync_io_cb, &iosync);
	while (ret == -EAGAIN) {
		/* try again, queue was full */
		blkdev_poll_req(bd);
		schedule();
		ret = blkdev_async_io(bd, start, len, write, target,
		                      _blkdev_sync_io_cb, &iosync);
	}
	if (ret < 0)
		return ret;

	/* wait for I/O completion */
	blkdev_poll_req(bd);
	while (trydown(&iosync.sem) == 0) {
		schedule(); /* yield CPU */
		blkdev_poll_req(bd);
	}

	return iosync.ret;
}
#define blkdev_sync_write(bd, start, len, buffer)	  \
	blkdev_sync_io((bd), (start), (len), 1, (buffer))
#define blkdev_sync_read(bd, start, len, buffer)	  \
	blkdev_sync_io((bd), (start), (len), 0, (buffer))

#endif /* _BLKDEV_H_ */
