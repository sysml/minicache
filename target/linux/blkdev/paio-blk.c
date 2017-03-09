/*
 * Linux block I/O glue
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
 * THIS HEADER MAY NOT BE EXTRACTED OR MODIFIED IN ANY WAY.
 *
 */
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <target/blkdev.h>

#ifdef BLKDEV_DEBUG
#define ENABLE_DEBUG
#endif
#include <debug.h>

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
    printd("Could not resolve path %s\n", id);
    return -errno;
  }
  return 0;
}

struct blkdev *open_blkdev(blkdev_id_t id, int mode)
{
  struct blkdev *bd;
  int err;

  /* TODO: replace id with a unique path */

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

  /* device is not opened yet */
  bd = malloc(sizeof(struct blkdev));
  if (!bd) {
    errno = ENOMEM;
    goto err;
  }  

  blkdev_id_cpy(bd->dev, id);
  bd->fd = open(bd->dev, mode & (O_RDWR | O_WRONLY));
  if (bd->fd < 0) {
    printd("Could not open %s\n", bd->dev);
    goto err_free_bd;
  }

  if (fstat(bd->fd, &bd->fd_stat) == -1) {
    printd("Could not retrieve stats from %s\n", bd->dev);
    goto err_close_fd;
  }
  if (!S_ISBLK(bd->fd_stat.st_mode) && !S_ISREG(bd->fd_stat.st_mode)) {
    printd("%s is not a block device or a regular file\n", bd->dev);
    errno = ENOTBLK;
    goto err_close_fd;
  }

  /* get device sector size in bytes */
  bd->ssize = bd->fd_stat.st_blksize;
  printd("%s has a block size of %"PRIu32" bytes\n", bd->dev, bd->ssize);

  /* get device size in bytes */
  if (S_ISBLK(bd->fd_stat.st_mode)) {
    err = ioctl(bd->fd, BLKGETSIZE64, &bd->size);
    if (err) {
      unsigned long size32;

      printd("BLKGETSIZE64 failed. Trying BLKGETSIZE\n");
      err = ioctl(bd->fd, BLKGETSIZE, &size32);
      if (err) {
	printd("Could not query device size from %s\n", bd->dev);
	goto err_close_fd;
      }
      bd->size = ((uint64_t) size32) / bd->ssize;
    }
  } else {
    bd->size = ((uint64_t) bd->fd_stat.st_size) / bd->ssize;
  }
  printd("%s has a size of %"PRIu64" bytes\n", bd->dev, (uint64_t) (bd->size * bd->ssize));

  bd->reqpool = alloc_simple_mempool(MAX_REQUESTS, sizeof(struct _blkdev_req));
  if (!bd->reqpool) {
    errno = ENOMEM;
    goto err_close_fd;
  }
  bd->mode = mode;
  bd->refcount = 1;
  bd->exclusive = !!(mode & O_EXCL);
  bd->reqq_head = NULL;
  bd->reqq_tail = NULL;

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

    /* TODO: check for enqueued IO */

    free_mempool(bd->reqpool);
    close(bd->fd);
    free(bd);
  }
}

static inline void _blkdev_finalize_req(struct _blkdev_req *req)
{
  struct mempool_obj *robj;
  int ret = 0;

  robj = req->p_obj;

  printd("Finalizing request %p\n", req);
  ret = (aio_return(&req->aiocb) == req->aiocb.aio_nbytes) ? 0 : -1;
  if (req->cb)
    req->cb(ret, req->cb_argp); /* user callback */

  mempool_put(robj);
}

void blkdev_poll_req(struct blkdev *bd)
{
  struct _blkdev_req *req;
  struct _blkdev_req *req_next;

  req = bd->reqq_head;
  while (req) {
    req_next = req->_next;
    
    printd("Checking request %p for completion\n", req);
    if (aio_error(&req->aiocb) != EINPROGRESS) {
      /* aio has completed
       * dequeue it from list and finalize it */
      if (req->_next)
	req->_next->_prev = req->_prev;
      else
	bd->reqq_tail = req->_prev;
      if (req->_prev)
	req->_prev->_next = req->_next;
      else
	bd->reqq_head = req->_next;
      
      _blkdev_finalize_req(req);
    }

    req = req_next;
  }
}

void _blkdev_sync_io_cb(int ret, void *argp)
{
	struct _blkdev_sync_io_sync *iosync = argp;

	iosync->ret = ret;
	iosync->done = 1;
}
