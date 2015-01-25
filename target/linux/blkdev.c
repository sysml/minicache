#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <target/blkdev.h>

/* NOTE: This is copied from linux kernel.
 * It probably makes sense to move this to mini-os's kernel.h */
#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif

#ifndef container_of
/**
 * container_of - cast a member of a structure out to the containing structure
 * @ptr:the pointer to the member.
 * @type:the type of the container struct this is embedded in.
 * @member:the name of the member within the struct.
 */
#define container_of(ptr, type, member) ({\
  const typeof( ((type *)0)->member ) *__mptr = (ptr);\
  (type *)( (char *)__mptr - offsetof(type,member) );})
#endif /* container_of */

struct blkdev *_open_bd_list = NULL;

int blkdev_id_parse(const char *id, blkdev_id_t *out)
{
  int ival, ret;

  /* get absolute path of file */
  if (realpath(id, *out) == NULL) {
    dprintf("Could not resolve path %s\n", id);
    return -errno;
  }
  return 0;
}

struct blkdev *open_blkdev(blkdev_id_t id, int mode)
{
  struct blkdev *bd;
  int err;

  bd = malloc(sizeof(struct blkdev));
  if (!bd) {
    errno = ENOMEM;
    goto err;
  }  

  /* search in blkdev list if device is already open */
  for (bd = _open_bd_list; bd != NULL; bd = bd->_next) {
    if (blkdev_id_cmp(blkdev_id(bd), id) == 0) {
      /* found: device is already open,
       *  now we check if it was/shall be opened
       *  exclusively and requested permissions
       *  are available */
      if (mode & O_EXCL ||
	  bd->exclusive) {
	errno = EBUSY;
	goto err;
      }
      if (((mode & O_WRONLY) && !(bd->mode & (O_WRONLY | O_RDWR))) ||
	  ((mode & O_RDWR) && !(bd->mode & O_RDWR))) {
	errno = EACCES;
	goto err;
      }
   
      ++bd->refcount;
      return bd;
    }
  }

  blkdev_id_cpy(bd->dev, id);
  bd->fd = open(bd->dev, mode & (O_RDWR | O_WRONLY));
  if (bd->fd < 0) {
    dprintf("Could not open %s\n", bd->dev);
    goto err_free_bd;
  }

  if (fstat(bd->fd, &bd->fd_stat) == -1) {
    dprintf("Could not retrieve stats from %s\n", bd->dev);
    goto err_close_fd;
  }
  if (!S_ISBLK(bd->fd_stat.st_mode) && !S_ISREG(bd->fd_stat.st_mode)) {
    dprintf("%s is not a block device or a regular file\n", bd->dev);
    errno = ENOTBLK;
    goto err_close_fd;
  }

  /* get device sector size in bytes */
  bd->ssize = bd->fd_stat.st_blksize;
  dprintf("%s has a block size of %"PRIu32" bytes\n", bd->dev, bd->ssize);

  /* get device size in bytes */
  if (S_ISBLK(bd->fd_stat.st_mode)) {
    err = ioctl(bd->fd, BLKGETSIZE64, &bd->size);
    if (err) {
      unsigned long size32;

      dprintf("BLKGETSIZE64 failed. Trying BLKGETSIZE\n");
      err = ioctl(bd->fd, BLKGETSIZE, &size32);
      if (err) {
	dprintf("Could not query device size from %s\n", bd->dev);
	goto err_close_fd;
      }
      bd->size = ((uint64_t) size32) / bd->ssize;
    }
  } else {
    bd->size = ((uint64_t) bd->fd_stat.st_size) / bd->ssize;
  }
  dprintf("%s has a size of %"PRIu64" bytes\n", bd->dev, (uint64_t) (bd->size * bd->ssize));

  bd->reqpool = alloc_simple_mempool(MAX_REQUESTS, sizeof(struct _blkdev_req));
  if (!bd->reqpool) {
    errno = ENOMEM;
    goto err_close_fd;
  }

  /* initialize libAIO */
  if (setup_io(MAX_REQUESTS, &bd->ctxp) < 0) {
    goto err_free_reqpool;
  }

  bd->mode = mode;
  bd->refcount = 1;
  bd->exclusive = !!(mode & O_EXCL);

  /* link new element to the head of _open_bd_list */
  bd->_prev = NULL;
  bd->_next = _open_bd_list;
  _open_bd_list = bd;
  if (bd->_next)
    bd->_next->_prev = bd;
  return bd;

 err_free_reqpool:
  free_mempool(bd->reqpool);
 err_close_fd:
  close(bd->fd);
 err_free_bd:
  free(bd);
 err:
  return NULL;
}

void close_blkdev(struct blkdev *bd)
{
  --bd->refcount;
  if (bd->refcount == 0) {
    /* unlink element from _open_bd_list */
    if (bd->_next)
      bd->_next->_prev = bd->_prev;
    if (bd->_prev)
      bd->_prev->_next = bd->_next;
    else
      _open_bd_list = bd->_next;

    BUG_ON(io_destroy(bd->ctxp) < 0);
    free_mempool(bd->reqpool);
    close(bd->fd);
    free(bd);
  }
}

void _blkdev_io_cb(io_context_t ctx, struct iocb *aiocb, long res, long res2)
{
  struct mempool_obj *robj;
  struct _blkdev_req *req;
  int ret = 0;

  req = container_of(aiocb, struct _blkdev_req, aiocb);
  robj = req->p_obj;

  if (req->cb)
    req->cb(ret, req->cb_argp); /* user callback */

  mempool_put(robj);
}
