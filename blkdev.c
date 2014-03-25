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

#define MAX_REQUESTS 4

struct blkdev *open_blkdev(unsigned int vbd_id, int mode)
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

  bd->vbd_id = vbd_id;
  snprintf(bd->nname, sizeof(bd->nname), "device/vbd/%u", vbd_id);

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
  xfree(bd);
 err:
  return NULL;
}

void close_blkdev(struct blkdev *bd)
{
  if (!bd)
	return;

  shutdown_blkfront(bd->dev);
  free_mempool(bd->reqpool);
  xfree(bd);
}

void _blkdev_async_io_cb(struct blkfront_aiocb *aiocb, int ret)
{
	struct mempool_obj *robj;
	struct _blkdev_req *req;
	struct blkdev *bd;

	req = container_of(aiocb, struct _blkdev_req, aiocb);
	robj = req->p_obj;
	bd = req->bd;

	if (req->cb)
		req->cb(ret, req->cb_argp); /* user callback */

	mempool_put(robj);
}

void _blkdev_sync_io_cb(int ret, void *argp)
{
	struct _blkdev_sync_io_sync *iosync = argp;

	iosync->ret = ret;
	up(&iosync->sem);
}
