/*
 * Simon's HashFS (SHFS) for Mini-OS
 *
 * Copyright(C) 2013-2014 NEC Laboratories Europe. All rights reserved.
 *                        Simon Kuenzer <simon.kuenzer@neclab.eu>
 */
#include <mini-os/os.h>
#include <mini-os/xmalloc.h>
#include <mini-os/types.h>
#include <stdint.h>
#include <errno.h>
#include <mempool.h>

#include "shfs.h"
#include "shfs_check.h"
#include "shfs_defs.h"
#include "shfs_btable.h"
#include "shfs_tools.h"
#ifdef SHFS_STATS
#include "shfs_stats_data.h"
#include "shfs_stats.h"
#endif

#ifdef SHFS_DEBUG
#define ENABLE_DEBUG
#endif
#include "debug.h"

#ifndef CACHELINE_SIZE
#define CACHELINE_SIZE 64
#endif

int shfs_mounted = 0;
unsigned int shfs_nb_open = 0;
struct semaphore shfs_mount_lock;
struct vol_info shfs_vol;

int init_shfs(void) {
	init_SEMAPHORE(&shfs_mount_lock, 1);

	return 0;
}

/**
 * This function tries to open a blkdev and checks if it has a valid SHFS label
 * On success, it returns the opened blkdev descriptor and the read disk chk0
 *  on *chk0
 * On errors, a null pointer is returned
 *
 * Note: chk0 has to be a buffer of 4096 bytes and be aligned to 4096 bytes
 */
static struct blkdev *shfs_checkopen_blkdev(unsigned int vbd_id, void *chk0)
{
	struct blkdev *bd;
	sector_t rlen;
	int ret;

	bd = open_blkdev(vbd_id, O_RDWR);
	if (!bd)
		goto err_out;

	if (blkdev_ssize(bd) > 4096 || blkdev_ssize(bd) < 512 ||
	    !POWER_OF_2(blkdev_ssize(bd))) {
		/* incompatible device */
		dprintf("Incompatible block size on vdb %u\n", vbd_id);
		goto err_close_bd;
	}

	/* read first chunk (considered as 4K) */
	rlen = 4096 / blkdev_ssize(bd);
	ret = blkdev_sync_read(bd, 0, rlen, chk0);
	if (ret < 0) {
		dprintf("Could not read from vdb %u: %d\n", vbd_id, ret);
		errno = -ret;
		goto err_close_bd;
	}

	/* Try to detect the SHFS disk label */
	ret = shfs_detect_hdr0(chk0);
	if (ret < 0) {
		dprintf("Invalid or unsupported SHFS label detected on vdb %u: %d\n", vbd_id, ret);
		errno = -ret;
		goto err_close_bd;
	}

	return bd;

 err_close_bd:
	close_blkdev(bd);
 err_out:
	return NULL;
}

/**
 * This function iterates over vbd_ids, tries to detect a SHFS label
 * and does the low-level setup for mounting a volume
 */
static int load_vol_cconf(unsigned int vbd_id[], unsigned int count)
{
	struct blkdev *bd;
	struct vol_member detected_member[MAX_NB_TRY_BLKDEVS];
	struct shfs_hdr_common *hdr_common;
	unsigned int i;
	uint8_t	m;
	unsigned int nb_detected_members;
	uint64_t min_member_size;
	int ret = 0;
	sector_t rlen;
	void *chk0;
	int inuse;

	if (count > MAX_NB_TRY_BLKDEVS) {
		ret = -EINVAL;
		goto err_out;
	}

	chk0 = _xmalloc(4096, 4096);
	if (!chk0) {
		ret = -ENOMEM;
		goto err_out;
	}

	/* Iterate over vbds and try to find those with a valid SHFS disk label */
	nb_detected_members = 0;
	for (i = 0; i < count; i++) {
		bd = shfs_checkopen_blkdev(vbd_id[i], chk0);
		if (!bd) {
			continue; /* try next device */
		}
		dprintf("SHFSv1 label on vbd %u detected\n", bd->vbd_id);

		/* chk0 now contains the first chunk read from disk */
		hdr_common = (void *)((uint8_t *) chk0 + BOOT_AREA_LENGTH);
		detected_member[nb_detected_members].bd = bd;
		uuid_copy(detected_member[nb_detected_members].uuid, hdr_common->member_uuid);
		nb_detected_members++;
	}
	if (nb_detected_members == 0) {
		ret = -ENODEV;
		goto err_free_chk0;
	}

	/* Load label from first detected member */
	rlen = 4096 / blkdev_ssize(detected_member[0].bd);
	ret = blkdev_sync_read(detected_member[0].bd, 0, rlen, chk0);
	if (ret < 0)
		goto err_close_bds;
	hdr_common = (void *)((uint8_t *) chk0 + BOOT_AREA_LENGTH);
	memcpy(shfs_vol.uuid, hdr_common->vol_uuid, 16);
	memcpy(shfs_vol.volname, hdr_common->vol_name, 16);
	shfs_vol.volname[17] = '\0'; /* ensure nullterminated volume name */
	shfs_vol.ts_creation = hdr_common->vol_ts_creation;
	shfs_vol.stripesize = hdr_common->member_stripesize;
	shfs_vol.stripemode = hdr_common->member_stripemode;
	if (shfs_vol.stripemode != SHFS_SM_COMBINED &&
	    shfs_vol.stripemode != SHFS_SM_INDEPENDENT) {
		dprintf("Stripe mode 0x%x is not supported\n", shfs_vol.stripemode);
		ret = -ENOTSUP;
		goto err_close_bds;
	}
	shfs_vol.chunksize = SHFS_CHUNKSIZE(hdr_common);
	shfs_vol.volsize = hdr_common->vol_size;

	/* Find and add members to the volume */
	dprintf("Searching for members of volume '%s'...\n", shfs_vol.volname);
	shfs_vol.nb_members = 0;
	for (i = 0; i < hdr_common->member_count; i++) {
		for (m = 0; m < nb_detected_members; ++m) {
			if (uuid_compare(hdr_common->member[i].uuid, detected_member[m].uuid) == 0) {
				/* found device */
				dprintf(" Member %u/%u is vbd %u\n",
				        i + 1, hdr_common->member_count,
				        detected_member[m].bd->vbd_id);
				shfs_vol.member[shfs_vol.nb_members].bd = detected_member[m].bd;
				uuid_copy(shfs_vol.member[shfs_vol.nb_members].uuid, detected_member[m].uuid);
				shfs_vol.nb_members++;
				break;
			}
		}

	}
	if (shfs_vol.nb_members != hdr_common->member_count) {
		dprintf("Could not find all members for volume '%s'\n",
		        shfs_vol.volname);
		ret = -ENOENT;
		goto err_close_bds;
	}

	/* chunk and stripe size -> retrieve a device sector factor for each device and
	 * also the alignment requirements for io buffers */
	shfs_vol.ioalign = 0;
	if (shfs_vol.stripesize > 32768 || shfs_vol.stripesize < 4096 ||
	    !POWER_OF_2(shfs_vol.stripesize)) {
		dprintf("Stripe size invalid on volume '%s'\n",
		        shfs_vol.volname);
		ret = -ENOENT;
		goto err_close_bds;
	}
	for (i = 0; i < shfs_vol.nb_members; ++i) {
		if (blkdev_ssize(shfs_vol.member[i].bd) > shfs_vol.ioalign)
			shfs_vol.ioalign = blkdev_ssize(shfs_vol.member[i].bd);
		shfs_vol.member[i].sfactor = shfs_vol.stripesize / blkdev_ssize(shfs_vol.member[i].bd);
		if (shfs_vol.member[i].sfactor == 0) {
			dprintf("Stripe size invalid on volume '%s'\n",
			       shfs_vol.volname);
			ret = -ENOENT;
			goto err_close_bds;
		}
	}

	/* calculate and check volume size */
	if (shfs_vol.stripemode == SHFS_SM_COMBINED)
		min_member_size = (shfs_vol.volsize + 1) * (uint64_t) shfs_vol.stripesize;
	else /* SHFS_SM_INTERLEAVED */
		min_member_size = ((shfs_vol.volsize + 1) / shfs_vol.nb_members) * (uint64_t) shfs_vol.stripesize;
	for (i = 0; i < shfs_vol.nb_members; ++i) {
		if (blkdev_size(shfs_vol.member[i].bd) < min_member_size) {
			dprintf("Member %u of volume '%s' is too small\n",
			       i, shfs_vol.volname);
			ret = -ENOENT;
			goto err_close_bds;
		}
	}

	/* clean-up: close non-used devices */
	for (m = 0; m < nb_detected_members; ++m) {
		inuse = 0;
		for (i = 0; i < shfs_vol.nb_members; ++i) {
			if (detected_member[m].bd == shfs_vol.member[i].bd) {
				inuse = 1;
				break;
			}
		}
		if (!inuse)
			close_blkdev(detected_member[m].bd);
	}

	xfree(chk0);
	return 0;

 err_close_bds:
	for (m = 0; m < nb_detected_members; ++m)
		close_blkdev(detected_member[m].bd);
 err_free_chk0:
	xfree(chk0);
 err_out:
	return ret;
}

/**
 * This function loads the hash configuration from chunk 1
 * (as defined in SHFS)
 * This function can only be called, after load_vol_cconf
 * established successfully the low-level setup of a volume
 * (required for chunk I/O)
 */
static int load_vol_hconf(void)
{
	struct shfs_hdr_config *hdr_config;
	void *chk1;
	int ret;

	chk1 = _xmalloc(shfs_vol.chunksize, 4096);
	if (!chk1) {
		ret = -ENOMEM;
		goto out;
	}

	dprintf("Loading SHFS configuration chunk...\n");
	ret = shfs_read_chunk(1, 1, chk1);
	if (ret < 0)
		goto out_free_chk1;

	hdr_config = chk1;
	shfs_vol.htable_ref                   = hdr_config->htable_ref;
	shfs_vol.htable_bak_ref               = hdr_config->htable_bak_ref;
	shfs_vol.htable_nb_buckets            = hdr_config->htable_bucket_count;
	shfs_vol.htable_nb_entries_per_bucket = hdr_config->htable_entries_per_bucket;
	shfs_vol.htable_nb_entries            = SHFS_HTABLE_NB_ENTRIES(hdr_config);
	shfs_vol.htable_nb_entries_per_chunk  = SHFS_HENTRIES_PER_CHUNK(shfs_vol.chunksize);
	shfs_vol.htable_len                   = SHFS_HTABLE_SIZE_CHUNKS(hdr_config, shfs_vol.chunksize);
	shfs_vol.hlen = hdr_config->hlen;
	ret = 0;

	/* brief configuration check */
	if (shfs_vol.htable_len == 0) {
		dprintf("Malformed SHFS configuration\n");
		ret = -ENOENT;
		goto out_free_chk1;
	}

 out_free_chk1:
	xfree(chk1);
 out:
	return ret;
}

/**
 * This function loads the hash table from the block device into memory
 * Note: load_vol_hconf() and local_vol_cconf() has to called before
 */
struct _load_vol_htable_aiot {
	struct semaphore done;
	chk_t left;
	int ret;
};

static void _load_vol_htable_cb(SHFS_AIO_TOKEN *t, void *cookie, void *argp)
{
	struct _load_vol_htable_aiot *aiot = (struct _load_vol_htable_aiot *) cookie;
	register int ioret;

	dprintf("*** AIO HTABLE CB (ret = %d / left = %lu) ***\n", aiot->ret, aiot->left - 1);
	BUG_ON(aiot->left == 0); /* This happens most likely when more requests are
	                          * sent to device than it can handle -> check MAX_REQUESTS 
	                          * in blkdev.h */

	ioret = shfs_aio_finalize(t);
	if (unlikely(ioret < 0))
		aiot->ret = ioret;
	--aiot->left;
	if (unlikely(aiot->left == 0))
		up(&aiot->done);
}

static int load_vol_htable(void)
{
	struct _load_vol_htable_aiot aiot;
	SHFS_AIO_TOKEN *aioret;
	struct shfs_hentry *hentry;
	struct shfs_bentry *bentry;
	void *chk_buf;
	unsigned int i;
	chk_t c;
	int ret;

	dprintf("Allocating chunk cache reference table (size: %lu B)...\n",
	        sizeof(void *) * shfs_vol.htable_len);
	shfs_vol.htable_chunk_cache = _xmalloc(sizeof(void *) * shfs_vol.htable_len, CACHELINE_SIZE);
	if (!shfs_vol.htable_chunk_cache) {
		ret = -ENOMEM;
		goto err_out;
	}
	memset(shfs_vol.htable_chunk_cache, 0, sizeof(void *) * shfs_vol.htable_len);

	/* read hash table from device */
	init_SEMAPHORE(&aiot.done, 0);
	aiot.left = shfs_vol.htable_len;
	aiot.ret = 0;
	for (c = 0; c < shfs_vol.htable_len; ++c) {
		/* allocate buffer and register it to htable chunk cache */
		dprintf("Allocate buffer for chunk %u of htable (size: %lu B, align: %lu)\n",
		        c, shfs_vol.chunksize, shfs_vol.ioalign);
		chk_buf = _xmalloc(shfs_vol.chunksize, shfs_vol.ioalign);
		if (!chk_buf) {
			dprintf("Could not alloc chunk %u\n", c);
			ret = -ENOMEM;
			goto err_free_chunkcache;
		}
		shfs_vol.htable_chunk_cache[c] = chk_buf;

	repeat_aio:
		dprintf("Setup async read for chunk %u\n", c);
		aioret = shfs_aread_chunk(shfs_vol.htable_ref + c, 1, chk_buf,
		                          _load_vol_htable_cb, &aiot, NULL);
		if (!aioret && errno == EAGAIN) {
			dprintf("Device is busy: Retrying...\n");
			shfs_poll_blkdevs();
			goto repeat_aio;
		}
		if (!aioret) {
			dprintf("Could not setup async read: %s\n", strerror(errno));
			aiot.left -= (shfs_vol.htable_len - c);
			goto err_cancel_aio;
		}
	}

	/* allocate bucket table */
	dprintf("Allocating btable...\n");
	shfs_vol.bt = shfs_alloc_btable(shfs_vol.htable_nb_buckets,
	                                shfs_vol.htable_nb_entries_per_bucket,
	                                shfs_vol.hlen);
	if (!shfs_vol.bt) {
		ret = -ENOMEM;
		goto err_free_chunkcache;
	}

	/* wait for I/O completion */
	dprintf("Waiting for I/O completion...\n");
	while (!trydown(&aiot.done))
		shfs_poll_blkdevs();
	if (aiot.ret < 0) {
		dprintf("There was an I/O error: Aborting...\n");
		ret = -EIO;
		goto err_free_btable;
	}

	/* feed bucket table */
	dprintf("Feeding hash table...\n");
	for (i = 0; i < shfs_vol.htable_nb_entries; ++i) {
		c = SHFS_HTABLE_CHUNK_NO(i, shfs_vol.htable_nb_entries_per_chunk);
		chk_buf = shfs_vol.htable_chunk_cache[c];

		hentry = (struct shfs_hentry *)((uint8_t *) chk_buf
                         + SHFS_HTABLE_ENTRY_OFFSET(i, shfs_vol.htable_nb_entries_per_chunk));
		bentry = shfs_btable_feed(shfs_vol.bt, i, hentry->hash);
		bentry->hentry = hentry;
		bentry->hentry_htchunk = c;
		bentry->hentry_htoffset = SHFS_HTABLE_ENTRY_OFFSET(i, shfs_vol.htable_nb_entries_per_chunk);
		bentry->refcount = 0;
		bentry->update = 0;
		init_SEMAPHORE(&bentry->updatelock, 1);
#ifdef SHFS_STATS
		memset(&bentry->hstats, 0, sizeof(bentry->hstats));
#endif
	}

	return 0;

 err_cancel_aio:
	if (aiot.left) {
		while (!trydown(&aiot.done))
			shfs_poll_blkdevs();
	}
	ret = -EIO;
	goto err_free_chunkcache;

 err_free_btable:
	shfs_free_btable(shfs_vol.bt);
 err_free_chunkcache:
	for (i = 0; i < shfs_vol.htable_len; ++i) {
		if (shfs_vol.htable_chunk_cache[i])
			xfree(shfs_vol.htable_chunk_cache[i]);
	}
	xfree(shfs_vol.htable_chunk_cache);
 err_out:
	return ret;
}

/**
 * Mount a SHFS volume
 * The volume is searched on the given list of VBD
 */
int mount_shfs(unsigned int vbd_id[], unsigned int count)
{
	unsigned int i;
	int ret;

	down(&shfs_mount_lock);

	if (count == 0) {
		ret = -EINVAL;
		goto err_out;
	}
	if (shfs_mounted) {
		ret = -EALREADY;
		goto err_out;
	}
	shfs_mounted = 0;

	/* load common volume information and open devices */
	ret = load_vol_cconf(vbd_id, count);
	if (ret < 0)
		goto err_out;

	/* a memory pool required for async I/O requests */
	shfs_vol.aiotoken_pool = alloc_simple_mempool(MAX_REQUESTS, sizeof(struct _shfs_aio_token));
	if (!shfs_vol.aiotoken_pool)
		goto err_close_members;
	shfs_mounted = 1; /* required by next function calls */

	/* load hash conf (uses shfs_sync_read_chunk) */
	ret = load_vol_hconf();
	if (ret < 0)
		goto err_free_aiotoken_pool;

	/* load htable (uses shfs_sync_read_chunk)
	 * This function also allocates htable_chunk_cache,
	 * htable_chunk_cache_state and btable */
	ret = load_vol_htable();
	if (ret < 0)
		goto err_close_members;

	/* a memory pool that is used by shfs_io for
	 * doing I/O */
	shfs_vol.chunkpool = alloc_mempool(CHUNKPOOL_NB_BUFFERS,
	                                   shfs_vol.chunksize,
	                                   shfs_vol.ioalign,
	                                   0, 0, NULL, NULL, 0);
	if (!shfs_vol.chunkpool) {
		shfs_mounted = 0;
		goto err_free_htable;
	}

#ifdef SHFS_STATS
	ret = shfs_init_mstats(shfs_vol.htable_nb_buckets,
	                       shfs_vol.htable_nb_entries_per_bucket,
	                       shfs_vol.hlen);
	if (!ret < 0) {
		shfs_mounted = 0;
		goto  err_free_chunkpool;
	}
#endif

	shfs_nb_open = 0;
	up(&shfs_mount_lock);
	return 0;

 err_free_chunkpool:
	free_mempool(shfs_vol.chunkpool);
 err_free_htable:
	for (i = 0; i < shfs_vol.htable_len; ++i) {
		if (shfs_vol.htable_chunk_cache[i])
			xfree(shfs_vol.htable_chunk_cache[i]);
	}
	xfree(shfs_vol.htable_chunk_cache);
	shfs_free_btable(shfs_vol.bt);
 err_free_aiotoken_pool:
	free_mempool(shfs_vol.aiotoken_pool);
 err_close_members:
	for(i = 0; i < shfs_vol.nb_members; ++i)
		close_blkdev(shfs_vol.member[i].bd);
	shfs_mounted = 0;
 err_out:
	up(&shfs_mount_lock);
	return ret;
}

/**
 * Unmounts a previously mounted SHFS volume
 * Note: Because semaphores are used to sync with opened files,
 *  when force is enabled, this function has to be called
 *  from a context that is different from the one of the main loop
 */
int umount_shfs(int force) {
	struct htable_el *el;
	struct shfs_bentry *bentry;
	unsigned int i;

	down(&shfs_mount_lock);
	if (shfs_mounted) {
		if (shfs_nb_open ||
		    mempool_free_count(shfs_vol.aiotoken_pool) < MAX_REQUESTS ||
		    mempool_free_count(shfs_vol.chunkpool) < CHUNKPOOL_NB_BUFFERS) {
			/* there are still open files and/or async I/O is happening */
			dprintf("Could not umount: SHFS is busy:\n");
			dprintf(" Open files:          %u\n",
			        shfs_nb_open);
			dprintf(" Infly AIO tokens:    %u\n",
			        MAX_REQUESTS - mempool_free_count(shfs_vol.aiotoken_pool));
			dprintf(" Infly chunk buffers: %u\n",
			        CHUNKPOOL_NB_BUFFERS - mempool_free_count(shfs_vol.chunkpool));

			if (!force) {
				up(&shfs_mount_lock);
				return -EBUSY;
			}

			/* lock entries */
			foreach_htable_el(shfs_vol.bt, el) {
				bentry = el->private;
				bentry->update = 1; /* forbid further open() */
				down(&bentry->updatelock); /* wait until file is closed */
			}
		}
		shfs_mounted = 0;

		free_mempool(shfs_vol.chunkpool);
		for (i = 0; i < shfs_vol.htable_len; ++i) {
			if (shfs_vol.htable_chunk_cache[i])
				xfree(shfs_vol.htable_chunk_cache[i]);
		}
		xfree(shfs_vol.htable_chunk_cache);
		shfs_free_btable(shfs_vol.bt);
		free_mempool(shfs_vol.aiotoken_pool);
		for(i = 0; i < shfs_vol.nb_members; ++i)
			close_blkdev(shfs_vol.member[i].bd); /* might call schedule() */
		shfs_vol.nb_members = 0;
#ifdef SHFS_STATS
		shfs_free_mstats();
#endif
	}
	up(&shfs_mount_lock);
	return 0;
}

/**
 * This function re-reads the hash table from the device
 * Since semaphores are used to sync with opened files,
 *  this function has to be called from a context that
 *  is different from the one of the main loop
 */
static int reload_vol_htable(void) {
#ifdef SHFS_STATS
	struct shfs_el_stats *el_stats;
#endif
	struct shfs_bentry *bentry;
	struct shfs_hentry *chentry;
	struct shfs_hentry *nhentry;
	struct mempool_obj *nchk_buf_obj;
	void *cchk_buf;
	void *nchk_buf;
	int chash_is_zero, nhash_is_zero;
	register chk_t c;
	register unsigned int e;
	int ret;

	nchk_buf_obj = mempool_pick(shfs_vol.chunkpool);
	if (!nchk_buf_obj) {
		ret = -errno;
		goto out;
	}
	nchk_buf = nchk_buf_obj->data;

	dprintf("Re-reading hash table...\n");
	for (c = 0; c < shfs_vol.htable_len; ++c) {
		/* read chunk from disk */
		ret = shfs_read_chunk(shfs_vol.htable_ref + c, 1, nchk_buf);
		if (ret < 0) {
			ret = -EIO;
			goto out_free_nchk_buf;
		}
		cchk_buf = shfs_vol.htable_chunk_cache[c];

		/* compare entries */
		for (e = 0; e < shfs_vol.htable_nb_entries_per_chunk; ++e) {
			chentry = (struct shfs_hentry *)((uint8_t *) cchk_buf
			          + SHFS_HTABLE_ENTRY_OFFSET(e, shfs_vol.htable_nb_entries_per_chunk));
			nhentry = (struct shfs_hentry *)((uint8_t *) nchk_buf
			          + SHFS_HTABLE_ENTRY_OFFSET(e, shfs_vol.htable_nb_entries_per_chunk));
			if (hash_compare(chentry->hash, nhentry->hash, shfs_vol.hlen)) {
				chash_is_zero = hash_is_zero(chentry->hash, shfs_vol.hlen);
				nhash_is_zero = hash_is_zero(nhentry->hash, shfs_vol.hlen);

				if (!chash_is_zero || !nhash_is_zero) {
					dprintf("Chunk %lu, entry %lu has been updated\n", c ,e);
					/* Update hash of entry
					 * Note: Any open file should not be affected, because
					 *  there is no hash table lookup needed again
					 *  The meta data is updated after all handles were closed
					 * Note: Since we lock the file in the next step, 
					 *  upcoming open of this entry will only be successful
					 *  when the update has been finished */
					bentry = shfs_btable_feed(shfs_vol.bt,
					          (c * shfs_vol.htable_nb_entries_per_chunk) + e,
					          nhentry->hash);
					/* lock entry */
					bentry->update = 1; /* forbid further open() */
					down(&bentry->updatelock); /* wait until files is closed */

#ifdef SHFS_STATS
					if (!chash_is_zero) {
						/* move current stats to miss table */
						el_stats = shfs_stats_from_mstats(chentry->hash);
						if (likely(el_stats != NULL))
							memcpy(el_stats, &bentry->hstats, sizeof(*el_stats));

						/* reset stats of element */
						memset(&bentry->hstats, 0, sizeof(*el_stats));
		       			} else {
						/* load stats from miss table */
						el_stats = shfs_stats_from_mstats(nhentry->hash);
						if (likely(el_stats != NULL))
							memcpy(&bentry->hstats, el_stats, sizeof(*el_stats));
						else
							memset(&bentry->hstats, 0, sizeof(*el_stats));

						/* delete entry from miss stats */
						shfs_stats_mstats_drop(nhentry->hash);
					}
#endif
					memcpy(chentry, nhentry, sizeof(*chentry));

					/* unlock entry */
					up(&bentry->updatelock);
					bentry->update = 0;
				}
			} else if (chentry->chunk  != nhentry->chunk  ||
			           chentry->offset != nhentry->offset ||
			           chentry->len    != nhentry->len) {
				/* in this case, just the file location has been moved
				 *
				 * Note: This is usually a bad thing but happens
				 * if the tools were misused
				 * Note: Since the hash digest did not change,
				 * the stats keep the same */
				/* lock entry */
				bentry->update = 1; /* forbid further open() */
				down(&bentry->updatelock); /* wait until files is closed */

				memcpy(chentry, nhentry, sizeof(*chentry));

				/* unlock entry */
				up(&bentry->updatelock);
				bentry->update = 0;
			} else {
				/* at least update name, mime type and creation timestamp
				 * (just in case if these values have been changed)
				 * These fields are completely independent to the file
				 * contents and should be read at once without yielding
				 * the CPU (e.g., snprintf, strncpy).
				 * Because of this, no locking is required */
				memcpy(chentry->name, nhentry->name, sizeof(chentry->name));
				memcpy(chentry->mime, nhentry->mime, sizeof(chentry->mime));
				chentry->ts_creation = nhentry->ts_creation;
			}
		}
	}

 out_free_nchk_buf:
	mempool_put(nchk_buf_obj);
 out:
	return ret;
}

/**
 * This function re-reads the hash table from the device
 * Since semaphores are used to sync with opened files,
 *  this function has to be called from a context that
 *  is different from the one of the main loop
 */
int remount_shfs(void) {
	int ret = 0;

	down(&shfs_mount_lock);
	if (!shfs_mounted) {
		ret = -ENODEV;
		goto out;
	}

	/* TODO: Re-read chunk0 and check if volume UUID still matches */

	ret = reload_vol_htable();
 out:
	up(&shfs_mount_lock);
	return ret;
}

/*
 * Note: Async I/O token data access is atomic since none of these functions can
 * be interrupted or yield the CPU. Even blkfront calls the callbacks outside
 * of the interrupt context via blkdev_poll_req() and there is only the
 * cooperative scheduler.
 */
static void _shfs_aio_cb(int ret, void *argp) {
	SHFS_AIO_TOKEN *t = argp;

	if (unlikely(ret < 0))
		t->ret = ret;
	--t->infly;

	if (unlikely(t->infly == 0)) {
		/* call user's callback */
		if (t->cb)
			t->cb(t, t->cb_cookie, t->cb_argp);
	}
}

SHFS_AIO_TOKEN *shfs_aio_chunk(chk_t start, chk_t len, int write, void *buffer,
                               shfs_aiocb_t *cb, void *cb_cookie, void *cb_argp)
{
	int ret;
	uint64_t num_req_per_member;
	sector_t start_sec;
	unsigned int m;
	uint8_t *ptr = buffer;
	struct mempool_obj *t_obj;
	SHFS_AIO_TOKEN *t;
	strp_t start_s;
	strp_t end_s;
	strp_t strp;


	if (!shfs_mounted) {
		errno = ENODEV;
		goto err_out;
	}

	switch (shfs_vol.stripemode) {
	case SHFS_SM_COMBINED:
		start_s = (strp_t) start * (strp_t) shfs_vol.nb_members;
		end_s = (strp_t) (start + len) * (strp_t) shfs_vol.nb_members;
		break;
	case SHFS_SM_INDEPENDENT:
	default:
		start_s = (strp_t) start + (strp_t) (shfs_vol.nb_members - 1);
		end_s = (strp_t) (start_s + len);
		break;
	}
	num_req_per_member = (end_s - start_s) / shfs_vol.nb_members;

	/* check if each member has enough request objects available for this operation */
	for (m = 0; m < shfs_vol.nb_members; ++m) {
		if (blkdev_avail_req(shfs_vol.member[m].bd) < num_req_per_member) {
			errno = EAGAIN;
			goto err_out;
		}
	}

	/* pick token */
	t_obj = mempool_pick(shfs_vol.aiotoken_pool);
	if (!t_obj) {
		errno = EAGAIN;
		goto err_out;
	}
	t = t_obj->data;
	t->p_obj = t_obj;
	t->ret = 0;
	t->infly = 0;
	t->cb = cb;
	t->cb_cookie = cb_cookie;
	t->cb_argp = cb_argp;

	/* setup requests */
	for (strp = start_s; strp < end_s; ++strp) {
		/* TODO: Try using shifts and masks
		 * instead of multiplies, mods and divs */
		m = strp % shfs_vol.nb_members;
		start_sec = (strp / shfs_vol.nb_members) * shfs_vol.member[m].sfactor;

		dprintf("shfs_aio_chunk: member=%u, start=%lus, len=%lus, ptr=@%p\n",
		        m, start_sec, shfs_vol.member[m].sfactor, ptr);
		ret = blkdev_async_io(shfs_vol.member[m].bd, start_sec, shfs_vol.member[m].sfactor,
		                      write, ptr, _shfs_aio_cb, t);
		if (unlikely(ret < 0)) {
			t->cb = NULL; /* erase callback */
			dprintf("Error while setting up async I/O request for member %u: %d. ", m, ret);
			dprintf("Cancelling request...\n");
			shfs_aio_wait(t);
			errno = -ret;
			goto err_free_token;
		}
		++t->infly;
		ptr += shfs_vol.stripesize;
	}
	return t;

 err_free_token:
	mempool_put(t_obj);
 err_out:
	return NULL;
}

void exit_shfs(void) {
	BUG_ON(shfs_mounted);
}
