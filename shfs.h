/*
 * Simon's HashFS (SHFS) for Mini-OS
 *
 * Copyright(C) 2013-2014 NEC Laboratories Europe. All rights reserved.
 *                        Simon Kuenzer <simon.kuenzer@neclab.eu>
 */
#ifndef _SHFS_H_
#define _SHFS_H_

#include <mini-os/types.h>
#include <stdint.h>
#include <semaphore.h>
#include <mempool.h>
#include "blkdev.h"

#include "shfs_defs.h"

#define MAX_NB_TRY_BLKDEVS 64
#define CHUNKPOOL_NB_BUFFERS 128

struct vol_member {
	struct blkdev *bd;
	uuid_t uuid;
	sector_t sfactor;
};

struct vol_info {
	uuid_t uuid;
	char volname[17];
	uint32_t chunksize;
	chk_t volsize;

	uint8_t nb_members;
	struct vol_member member[SHFS_MAX_NB_MEMBERS];
	uint32_t stripesize;

	struct shfs_btable *bt;
	void **htable_chunk_cache;
	int *htable_chunk_cache_state;
	chk_t htable_ref;
	chk_t htable_bak_ref;
	chk_t htable_len;
	uint32_t htable_nb_buckets;
	uint32_t htable_nb_entries;
	uint32_t htable_nb_entries_per_bucket;
	uint32_t htable_nb_entries_per_chunk;
	uint8_t hlen;

	struct mempool *aiotoken_pool; /* async io tokens */
	struct mempool *chunkpool; /* buffers for chunk I/O */
};

/* htable_chunk_cache_state */
#define CCS_LOADED   0x01
#define CCS_MODIFIED 0x02

extern struct vol_info shfs_vol;
extern struct semaphore shfs_mount_lock;
extern volatile int shfs_mounted;
extern volatile unsigned int shfs_nb_open;

int init_shfs(void);
int mount_shfs(unsigned int vbd_id[], unsigned int count);
int umount_shfs(void);
void exit_shfs(void);

static inline void shfs_poll_blkdevs(void) {
	unsigned int i;

	if (likely(shfs_mounted))
		for(i = 0; i < shfs_vol.nb_members; ++i)
			blkdev_poll_req(shfs_vol.member[i].bd);
}

/**
 * Fast I/O: asynchronous I/O for volume chunks
 * A request is done via shfs_aio_chunk(). This function returns immediately
 * after the I/O request was set up.
 * Afterwards, the caller has to wait for the I/O completion via
 * tests on shfs_aio_is_done() or by calling shfs_aio_wait() or using a
 * function callback registration on shfs_aio_chunk().
 * The result (return code) of the I/O operation is retrieved via
 * shfs_aio_finalize() (can be called within the user's callback).
 */
struct _shfs_aio_token;
typedef struct _shfs_aio_token SHFS_AIO_TOKEN;
typedef void (shfs_aiocb_t)(SHFS_AIO_TOKEN *t, void *cookie, void *argp);
struct _shfs_aio_token {
	/** this struct has only private data **/
	struct mempool_obj *p_obj;
	uint64_t infly;
	int ret;

	shfs_aiocb_t *cb;
	void *cb_cookie;
	void *cb_argp;
};

/*
 * Setups a asynchronous I/O operation and returns a token
 * NULL is returned if the async I/O operation could not be set up
 * The callback registration is optional and can be seen as an alternative way
 * to wait for the I/O completation compared to using shfs_aio_is_done()
 * or shfs_aio_wait()
 * cb_cookie and cb_argp are user definable values that get passed
 * to the user defined callback.
 */
SHFS_AIO_TOKEN *shfs_aio_chunk(chk_t start, chk_t len, int write, void *buffer,
                               shfs_aiocb_t *cb, void *cb_cookie, void *cb_argp);
#define shfs_aread_chunk(start, len, buffer, cb, cb_cookie, cb_argp)	  \
	shfs_aio_chunk((start), (len), 0, (buffer), (cb), (cb_cookie), (cb_argp))
#define shfs_awrite_chunk(start, len, buffer, cb, cb_cookie, cb_argp) \
	shfs_aio_chunk((start), (len), 1, (buffer), (cb), (cb_cookie), (cb_argp))

/*
 * Returns 1 if the I/O operation has finished, 0 otherwise
 */
#define shfs_aio_is_done(t)	  \
	(!(t) || (t)->infly == 0)

/*
 * Busy-waiting until the async I/O operation is completed
 *
 * Note: This function will end up in a deadlock when there is no
 * SHFS volume mounted
 */
#define shfs_aio_wait(t) \
	while (!shfs_aio_is_done((t))) { \
		shfs_poll_blkdevs(); \
		if (!shfs_aio_is_done((t)))  \
			schedule(); \
	}

/*
 * Destroys an asynchronous I/O token after the I/O completed
 * This function returns the return code of the IO operation
 *
 * Note: This function has and can only be called after an I/O is done!
 */
static inline int shfs_aio_finalize(SHFS_AIO_TOKEN *t)
{
	int ret;

	BUG_ON(t->infly != 0);
	ret = t->ret;
	mempool_put(t->p_obj);

	return ret;
}

/**
 * Slow I/O: sequential sync I/O for volume chunks
 * These functions are intended to be used during mount/umount time
 */
static inline int shfs_io_chunk(chk_t start, chk_t len, int write, void *buffer) {
	SHFS_AIO_TOKEN *t;

	t = shfs_aio_chunk(start, len, write, buffer, NULL, NULL, NULL);
	if (!t)
		return -errno;
	shfs_aio_wait(t);
	return shfs_aio_finalize(t);
}
#define shfs_read_chunk(start, len, buffer) \
	shfs_io_chunk((start), (len), 0, (buffer))
#define shfs_write_chunk(start, len, buffer) \
	shfs_io_chunk((start), (len), 1, (buffer))

#endif /* _SHFS_H_ */
