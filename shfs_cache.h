#ifndef _SHFS_CACHE_
#define _SHFS_CACHE_

#include "shfs_cache.h"
#include "shfs_defs.h"
#include "shfs.h"

#include "dlist.h"
#include "mempool.h"

struct shfs_cache_entry {
	struct mempool_obj *pobj;

	chk_t addr;
	uint32_t refcount;

	dlist_el(alist);
	dlist_el(clist);

	void *buffer;
	int invalid; /* I/O didn't succeed on this buffer */

	SHFS_AIO_TOKEN *t;
	struct {
		SHFS_AIO_TOKEN *first;
		SHFS_AIO_TOKEN *last;
	} aio_chain;
};

struct shfs_cache_htel {
	struct dlist_head clist; /* collision list */
	uint32_t len;
};

struct shfs_cache {
	struct mempool *pool;
	uint32_t htlen;
	uint32_t htmask;

	struct dlist_head alist; /* list of available (loaded) but unreferenced entries */
	struct shfs_cache_htel htable[]; /* hash table (all loaded entries (incl. referenced)) */
};

int shfs_alloc_cache(uint32_t nb_bffs, uint8_t ht_order);
void shfs_flush_cache(void); /* releases unreferenced buffers */
void shfs_free_cache(void);

/*
 * Function to read one chunk from the SHFS volume through the cache
 *
 * There are two cases of success
 *  (1) the cache can serve a request directly
 *  (2) the cache initiated an AIO request
 *  Like the direct AIO interfaces, a callback function can be passed that gets
 *  called when the I/O operation has completed or the SHFS_AIO_TOKEN can be polled.
 *
 * If the cache could serve the request directly,
 *  0 is returned and *cce_out points to the corresponding cache entry that holds
 *    the chunk data on its buffer
 *
 * If an AIO operation was initiated
 *  1 is returned and *t_out points to the corresponding SHFS_AIO_TOKEN that can be checked.
 *    *cce_out points to a newly created cache entry that will hold the data after the
 *    I/O operation completed
 *
 * a negative value is returned when there was an error:
 *  -EINVAL: Invalid chunk address
 *  -EAGAIN: Cannot perform operation currently, all cache buffers in use and could
 *           not create a new one or volume cannot handle a new request currently
 *
 * A cache buffer is reserved until it is released back to the cache. That's
 * why shfs_cache_release() needs to be called after the buffer is not required
 * anymore.
 *
 * Note: This cache implementation can only be used for read-only operation
 *       because buffers can be shared.
 */
int shfs_cache_aread(chk_t addr, shfs_aiocb_t *cb, void *cb_cookie, void *cb_argp, struct shfs_cache_entry **cce_out, SHFS_AIO_TOKEN **t_out);

void shfs_cache_release(struct shfs_cache_entry *cce); /* release a shfs cache buffer */

/* synchronous I/O read using the cache */
static inline struct shfs_cache_entry *shfs_cache_read(chk_t addr)
{
	struct shfs_cache_entry *cce;
	SHFS_AIO_TOKEN *t;
	int ret;

	do {
		ret = shfs_cache_aread(addr, NULL, NULL, NULL, &cce, &t);
		if (ret == -EAGAIN)
			schedule();
	} while (ret == -EAGAIN);
	if (ret < 0) {
		errno = -ret;
		return NULL;
	}
	if (ret == 1) {
		/* wait for completion */
		shfs_aio_wait(t);
		ret = shfs_aio_finalize(t);
		if (ret < 0) {
			/* I/O failed */
			shfs_cache_release(cce);
			errno = -ret;
			return NULL;
		}
	} else if (unlikely(cce->invalid)) {
		/* cache buffer is broken */
		shfs_cache_release(cce);
		errno = EIO;
		return NULL;
	}
	return cce;
}


#endif /* _SHFS_CACHE_ */
