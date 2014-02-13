#ifndef _BLKDEV_H_
#define _BLKDEV_H_

#include <mini-os/blkfront.h>
#include <mempool.h>
#include <fcntl.h>

#define MAX_DISKSIZE (1ll << 40) /* 1 TB */

struct blkdev {
  struct blkfront_dev *dev;
  struct blkfront_info info;
  struct mempool *reqpool;
  char nname[128];
  int mode;
};

struct _blkdev_req {
  struct mempool_obj *p_obj; /* reference to dependent memory pool object */
  struct blkfront_aiocb aiocb;
  struct blkdev *bd;
  uint64_t sector;
  size_t nb_sectors;
  int write;
  void (*cb_func)(struct blkdev *bd, uint64_t sector, size_t nb_sectors, int write, int ret, void *argp);
  void *cb_func_argp;
};

struct blkdev *open_blkdev(unsigned int vdb_id, int mode);
void close_blkdev(struct blkdev *bd);

static inline uint64_t blkdev_sectors(struct blkdev *bd)
{
  /* WORKAROUND: blkfront cannot handle > 1TB -> limit the disk size */
  if (((uint64_t) bd->info.sectors * (uint64_t) bd->info.sector_size) > MAX_DISKSIZE)
	return (MAX_DISKSIZE / (uint64_t) bd->info.sector_size);
  return (uint64_t) bd->info.sectors;
}

#define blkdev_ssize(bd) ((bd)->info.sector_size) /* returned type: unsigned */
#define blkdev_size(bd) (blkdev_sectors((bd)) * (uint64_t) blkdev_ssize((bd))) /* returned type: uint64_t */

#define blkdev_avail_req(bd) mempool_free_count((bd)->reqpool)

void _blkdev_req_cb(struct blkfront_aiocb *aiocb, int ret);

/*
 * NOTE: buffer needs to be aligned to device sector size
 */
static inline int blkdev_submit_req_nocheck(struct blkdev *bd, uint64_t sector, size_t nb_sectors, int write, void *buffer, 
											void (*cb_func)(struct blkdev *, uint64_t, size_t, int, int, void *), void *cb_func_argp)
{
  struct mempool_obj *robj;
  struct _blkdev_req *req;

  robj = mempool_pick(bd->reqpool);
  if (unlikely(!robj)) {
	errno = EAGAIN; /* too many requests in work, currently */
	return -1;
  }

  req = robj->data;
  req->p_obj = robj;

  req->aiocb.data = NULL;
  req->aiocb.aio_dev = bd->dev;
  req->aiocb.aio_buf = buffer;
  req->aiocb.aio_nbytes = nb_sectors * blkdev_ssize(bd);
  req->aiocb.aio_offset = (off_t) (sector * blkdev_ssize(bd));
  req->aiocb.aio_cb = _blkdev_req_cb;
  req->bd = bd;
  req->sector = sector;
  req->nb_sectors = nb_sectors;
  req->write = write;
  req->cb_func = cb_func;
  req->cb_func_argp = cb_func_argp;

  blkfront_aio(&(req->aiocb), write);
  return 0;
}

static inline int blkdev_submit_req(struct blkdev *bd, uint64_t sector, size_t nb_sectors, int write, void *buffer, 
									void (*cb_func)(struct blkdev *, uint64_t, size_t, int, int, void *), void *cb_func_argp)
{
  if (unlikely((!write && !(bd->mode & O_RDONLY)) &&
			   ( write && !(bd->mode & O_WRONLY)))) {
	/* write access on non-writable device or read access on non-readable device */
	errno = EACCES;
	return -1;
  }

  if (unlikely((nb_sectors * blkdev_ssize(bd)) / PAGE_SIZE > BLKIF_MAX_SEGMENTS_PER_REQUEST)) {
	/* request too big -> blockfront cannot handle it with a single request */
	errno = ENXIO;
	return -1;
  }

  if (unlikely(((uint64_t) buffer) & ((uint64_t) blkdev_ssize(bd) - 1))) {
	/* buffer is not aligned to device sector size */
	errno = EINVAL;
    return -1;
  }

  return blkdev_submit_req_nocheck(bd, sector, nb_sectors, write, buffer, cb_func, cb_func_argp);
}

#define blkdev_poll_req(bd) blkfront_aio_poll((bd)->dev);

#endif /* _BLKDEV_H_ */
