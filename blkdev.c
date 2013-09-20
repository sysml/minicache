#include <mini-os/os.h>
#include <mini-os/types.h>
#include <mini-os/xmalloc.h>
#include <limits.h>
#include <errno.h>

#include "blkdev.h"

#ifndef container_of
/* NOTE: This is copied from linux kernel.
 * It probably makes sense to move this to mini-os's kernel.h */
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

#define MAX_REQUESTS 16

struct blkdev *open_blkdev(unsigned int vdb_id, int mode)
{
  struct blkdev *bd;

  bd = xmalloc(struct blkdev);
  if (!bd) {
	errno = ENOMEM;
	goto err;
  }

  bd->reqpool = alloc_simple_mempool(MAX_REQUESTS, sizeof(struct _blkdev_req));
  if (!bd->reqpool) {
	errno = ENOMEM;
	goto err_free_bd;
  }

  snprintf(bd->nname, sizeof(bd->nname), "device/vbd/%u", vdb_id);

  bd->dev = init_blkfront(bd->nname, &(bd->info));
  if (!bd->dev) {
  	errno = ENODEV;
	goto err_free_reqpool;
  }

  bd->mode = mode & bd->info.mode;
  if (((mode & O_WRONLY) && !(bd->info.mode & O_WRONLY)) ||
	  ((mode & O_RDONLY) && !(bd->info.mode & O_RDONLY))) {
	errno = EACCES;
	goto err_shutdown_blkfront;
  }
  return bd;

 err_shutdown_blkfront:
  shutdown_blkfront(bd->dev);
 err_free_reqpool:
  free_mempool(bd->reqpool);
 err_free_bd:
  free(bd);
 err:
  return NULL;
}

void close_blkdev(struct blkdev *bd)
{
  if (!bd)
	return;

  shutdown_blkfront(bd->dev);
  free_mempool(bd->reqpool);
  free(bd);
}

void _blkdev_req_cb(struct blkfront_aiocb *aiocb, int ret)
{
  struct mempool_obj *robj;
  struct _blkdev_req *req;
  struct blkdev *bd;
  void (*cb_func)(struct blkdev *bd, uint64_t sector, size_t nb_sectors, int write, int ret, void *argp);

  req = container_of(aiocb, struct _blkdev_req, aiocb);
  robj = req->p_obj;
  bd = req->bd;
  cb_func = req->cb_func;

  if (cb_func)
	cb_func(bd, req->sector, req->nb_sectors, req->write, ret, req->cb_func_argp); /* call callback */

  mempool_put(robj);
}
