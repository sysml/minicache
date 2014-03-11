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
#include "shfs_htable.h"
#include "shfs_tools.h"

#ifndef CACHELINE_SIZE
#define CACHELINE_SIZE 64
#endif

volatile int shfs_mounted = 0;
volatile unsigned int shfs_nb_open = 0;
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
#ifdef SHFS_DEBUG
		printf("Incompatible block size on vdb %u\n", vbd_id);
#endif
		goto err_close_bd;
	}

	/* read first chunk (considered as 4K) */
	rlen = 4096 / blkdev_ssize(bd);
	ret = blkdev_sync_read(bd, 0, rlen, chk0);
	if (ret < 0) {
#ifdef SHFS_DEBUG
		printf("Could not read from vdb %u: %d\n", vbd_id, ret);
#endif
		errno = -ret;
		goto err_close_bd;
	}

	/* Try to detect the SHFS disk label */
	ret = shfs_detect_hdr0(chk0);
	if (ret < 0) {
#ifdef SHFS_DEBUG
		printf("Invalid or unsupported SHFS label detected on vdb %u: %d\n", vbd_id, ret);
#endif
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
	unsigned int i, j, m;
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
#ifdef SHFS_DEBUG
		printf("SHFSv1 label on vbd %u detected\n", bd->vbd_id);
#endif
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
	shfs_vol.stripesize = hdr_common->member_stripesize;
	shfs_vol.chunksize = SHFS_CHUNKSIZE(hdr_common);
	shfs_vol.volsize = hdr_common->vol_size;

	/* Find and add members to the volume */
	shfs_vol.nb_members = 0;
	for (i = 0; i < hdr_common->member_count; i++) {
		for (m = 0; m < nb_detected_members; ++m) {
			if (uuid_compare(hdr_common->member[i].uuid, detected_member[m].uuid) == 0) {
				/* found device but was this member already added (malformed label)? */
				for (j = 0; j < shfs_vol.nb_members; ++j) {
					if (uuid_compare(shfs_vol.member[j].uuid,
					                 hdr_common->member[i].uuid) == 0) {
						ret = -EEXIST;
						goto err_close_bds;
					}
				}
				shfs_vol.member[shfs_vol.nb_members].bd = detected_member[m].bd;
				uuid_copy(shfs_vol.member[shfs_vol.nb_members].uuid, detected_member[m].uuid);
				shfs_vol.nb_members++;
				continue;
			}
		}

	}
	if (shfs_vol.nb_members != hdr_common->member_count) {
#ifdef SHFS_DEBUG
		printf("Could not find correct member to vbd mapping for volume '%s'\n",
		       shfs_vol.volname);
#endif /* SHFS_DEBUG */
		ret = -ENOENT;
		goto err_close_bds;
	}

	/* chunk and stripe size -> retrieve a device sector factor for each device */
	if (shfs_vol.stripesize > 32768 || shfs_vol.stripesize < 4096 ||
	    !POWER_OF_2(shfs_vol.stripesize)) {
#ifdef SHFS_DEBUG
		printf("Stripe size invalid on volume '%s'\n",
		       shfs_vol.volname);
#endif /* SHFS_DEBUG */
		ret = -ENOENT;
		goto err_close_bds;
	}
	for (i = 0; i < shfs_vol.nb_members; ++i) {
		shfs_vol.member[i].sfactor = shfs_vol.stripesize / blkdev_ssize(shfs_vol.member[i].bd);
		if (shfs_vol.member[i].sfactor == 0) {
#ifdef SHFS_DEBUG
			printf("Stripe size invalid on volume '%s'\n",
			       shfs_vol.volname);
#endif /* SHFS_DEBUG */
			ret = -ENOENT;
			goto err_close_bds;
		}
	}

	/* calculate and check volume size */
	min_member_size = (shfs_vol.volsize / shfs_vol.nb_members) * (uint64_t) shfs_vol.chunksize;
	for (i = 0; i < shfs_vol.nb_members; ++i) {
		if (blkdev_size(shfs_vol.member[i].bd) < min_member_size) {
#ifdef SHFS_DEBUG
			printf("Member %u of volume '%s' is too small\n",
			       i, shfs_vol.volname);
#endif /* SHFS_DEBUG */
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

#ifdef SHFS_DEBUG
	printf("Load SHFS configuration chunk\n");
#endif /* SHFS_DEBUG */
	ret = shfs_sync_read_chunk(1, 1, chk1);
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

 out_free_chk1:
	xfree(chk1);
 out:
	return ret;
}

/**
 * This function loads the hash table from the block device into memory
 * Note: load_vol_hconf() and local_vol_cconf() has to called before
 */
static int load_vol_htable(void)
{
	struct shfs_hentry *hentry;
	struct shfs_bentry *bentry;
	void *chk_buf;
	chk_t cur_chk, cur_htchk;
	unsigned int i;
	int ret;

	/* allocate bucket table */
#ifdef SHFS_DEBUG
	printf("Allocating btable...\n");
#endif /* SHFS_DEBUG */
	shfs_vol.bt = shfs_alloc_btable(shfs_vol.htable_nb_buckets,
	                                shfs_vol.htable_nb_entries_per_bucket,
	                                shfs_vol.hlen);
	if (!shfs_vol.bt) {
		ret = -ENOMEM;
		goto err_out;
	}

	/* allocate chunk cache reference table */
#ifdef SHFS_DEBUG
	printf("Allocating chunk cache reference table...\n");
#endif /* SHFS_DEBUG */
	shfs_vol.htable_chunk_cache_state = _xmalloc(sizeof(int) * shfs_vol.htable_len, CACHELINE_SIZE);
	if (!shfs_vol.htable_chunk_cache_state) {
		ret = -ENOMEM;
		goto err_free_btable;
	}
	shfs_vol.htable_chunk_cache = _xmalloc(sizeof(void *) * shfs_vol.htable_len, CACHELINE_SIZE);
	if (!shfs_vol.htable_chunk_cache) {
		ret = -ENOMEM;
		goto err_free_chunkcachestate;
	}
	memset(shfs_vol.htable_chunk_cache_state, 0, sizeof(int *) * shfs_vol.htable_len);

	/* load hash table chunk-wise and fill-out btable metadata */
#ifdef SHFS_DEBUG
	printf("Reading hash table...\n");
#endif
	chk_buf = NULL;
	cur_chk = 0;
	for (i = 0; i < shfs_vol.htable_nb_entries; ++i) {
		cur_htchk = SHFS_HTABLE_CHUNK_NO(i, shfs_vol.htable_nb_entries_per_chunk);
		if (cur_chk != cur_htchk || !chk_buf) {
			/* allocate buffer and register it to htable chunk cache */
			chk_buf = _xmalloc(shfs_vol.chunksize, 4096);
			if (!chk_buf) {
				ret = -ENOMEM;
				goto err_free_chunkcache;
			}
			shfs_vol.htable_chunk_cache[cur_htchk]       = chk_buf;
			shfs_vol.htable_chunk_cache_state[cur_htchk] = CCS_LOADED;

			ret = shfs_sync_read_chunk(cur_htchk + shfs_vol.htable_ref, 1, chk_buf);
			if (ret < 0) {
				goto err_free_chunkcache;
			}
			cur_chk = cur_htchk;
		}

		bentry = shfs_btable_pick(shfs_vol.bt, i);
		bentry->hentry_htchunk  = cur_htchk;
		bentry->hentry_htoffset = SHFS_HTABLE_ENTRY_OFFSET(i, shfs_vol.htable_nb_entries_per_chunk);
		hentry = (struct shfs_hentry *)((uint8_t *) chk_buf + bentry->hentry_htoffset);
		hash_copy(bentry->hash, hentry->hash, shfs_vol.hlen);
	}

	return 0;

 err_free_chunkcache:
	for (i = 0; i < shfs_vol.htable_len; ++i) {
		if (shfs_vol.htable_chunk_cache_state[i] & CCS_LOADED)
			xfree(shfs_vol.htable_chunk_cache[i]);
	}
	xfree(shfs_vol.htable_chunk_cache);
 err_free_chunkcachestate:
	xfree(shfs_vol.htable_chunk_cache_state);
 err_free_btable:
	shfs_free_btable(shfs_vol.bt);
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

	BUG_ON(shfs_mounted);
	if (count == 0) {
		ret = -EINVAL;
		goto err_out;
	}

	/* load common volume information and open devices */
	ret = load_vol_cconf(vbd_id, count);
	if (ret < 0)
		goto err_out;
	shfs_mounted = 1;

	/* load hash conf (uses shfs_sync_read_chunk) */
	ret = load_vol_hconf();
	if (ret < 0)
		goto err_close_members;

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
	                                   4096,
	                                   0, 0, NULL, NULL, 0);
	if (!shfs_vol.chunkpool) {
		shfs_mounted = 0;
		goto err_free_htable;
	}

	shfs_nb_open = 0;
	up(&shfs_mount_lock);
	return 0;

 err_free_htable:
	for (i = 0; i < shfs_vol.htable_len; ++i) {
		if (shfs_vol.htable_chunk_cache_state[i] & CCS_LOADED)
			xfree(shfs_vol.htable_chunk_cache[i]);
	}
	xfree(shfs_vol.htable_chunk_cache);
	xfree(shfs_vol.htable_chunk_cache_state);
	shfs_free_btable(shfs_vol.bt);
 err_close_members:
	for(i = 0; i < shfs_vol.nb_members; ++i)
		close_blkdev(shfs_vol.member[i].bd);
 err_out:
	shfs_mounted = 0;
	up(&shfs_mount_lock);
	return ret;
}

/**
 * Unmounts a previously mounted SHFS volume
 */
int umount_shfs(void) {
	unsigned int i;

	down(&shfs_mount_lock);
	if (shfs_mounted) {
		if (shfs_nb_open ||
		    mempool_free_count(shfs_vol.chunkpool) < CHUNKPOOL_NB_BUFFERS) {
			/* there are still open files */
			up(&shfs_mount_lock);
			return -EBUSY;
		}

		free_mempool(shfs_vol.chunkpool);
		for (i = 0; i < shfs_vol.htable_len; ++i) {
			if (shfs_vol.htable_chunk_cache_state[i] & CCS_LOADED)
				xfree(shfs_vol.htable_chunk_cache[i]);
		}
		xfree(shfs_vol.htable_chunk_cache);
		xfree(shfs_vol.htable_chunk_cache_state);
		shfs_free_btable(shfs_vol.bt);
		for(i = 0; i < shfs_vol.nb_members; ++i)
			close_blkdev(shfs_vol.member[i].bd);
	}
	shfs_mounted = 0;
	up(&shfs_mount_lock);
	return 0;
}

int shfs_sync_io_chunk(chk_t start, chk_t len, int write, void *buffer)
{
	int ret;
	chk_t end, c;
	sector_t start_sec, len_sec;
	unsigned int m;
	uint8_t *wptr = buffer;

	if (!shfs_mounted)
		return -ENODEV;

	end = start + len;
	for (c = start; c < end; c++) {
		for (m = 0; m < shfs_vol.nb_members; ++m) {
			/* TODO: Try using shift instead of multiply */
			start_sec = c * shfs_vol.member[m].sfactor;
			len_sec = shfs_vol.member[m].sfactor;
#ifdef SHFS_DEBUG
			printf("blkdev_sync_io member=%u, start=%lus, len=%lus, wptr=%p\n",
			       m, start_sec, len_sec, wptr);
#endif /* SHFS_DEBUG */
			ret = blkdev_sync_io(shfs_vol.member[m].bd, start_sec, len_sec, write, wptr);
			if (ret < 0) {
#ifdef SHFS_DEBUG
				printf("Error while reading from member %u: %d\n", m, ret);
#endif /* SHFS_DEBUG */
				return ret;
			}
			wptr += shfs_vol.stripesize;
		}
	}

	return 0;
}

void exit_shfs(void) {
	BUG_ON(shfs_mounted);
}
