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

volatile int shfs_mounted = 0;
struct semaphore shfs_mount_lock;
struct vol_info shfs_vol;

int init_shfs(void) {
	init_SEMAPHORE(&shfs_mount_lock, 1);

	return 0;
}

static int load_vol_cconf(struct blkdev *bd[], unsigned int count)
{
	struct vol_member detected_member[count];
	struct shfs_hdr_common *hdr_common;
	sector_t rlen;
	void *chk0;
	unsigned int i, m;
	unsigned int nb_detected_members;
	uint64_t min_member_size;
	int ret = 0;

	chk0 = _xmalloc(4096, 4096);
	if (!chk0) {
		ret = -ENOMEM;
		goto out;
	}

	/* Iterate over vbds and try to find those with a SHFS disk label */
	nb_detected_members = 0;
	for (i = 0; i < count; i++) {
		if (blkdev_ssize(bd[i]) > 4096 || blkdev_ssize(bd[i]) < 512 ||
		    !POWER_OF_2(blkdev_ssize(bd[i]))) {
			/* incompatible device */
#ifdef SHFS_DEBUG
			printf("Incompatible block size on vdb %u\n", bd[i]->vbd_id);
#endif /* SHFS_DEBUG */
			continue; /* try next device */
		}
		/* read first chunk (considered as 4K) */
		rlen = 4096 / blkdev_ssize(bd[i]);
		ret = blkdev_sync_read(bd[i], 0, rlen, chk0);
		if (ret < 0) {
#ifdef SHFS_DEBUG
			printf("Could not read from vdb %u: %d\n", bd[i]->vbd_id, ret);
#endif /* SHFS_DEBUG */
			continue; /* try next disk */
		}

		/* Try to detect the SHFS disk label */
		ret = shfs_detect_hdr0(chk0);
		if (ret < 0) {
#ifdef SHFS_DEBUG
			printf("No valid or supported SHFS label detected on vdb %u: %d\n",
			       bd[i]->vbd_id, ret);
#endif /* SHFS_DEBUG */
			continue; /* try next disk */
		}
#ifdef SHFS_DEBUG
		printf("SHFSv1 label on vbd %u detected\n", bd[i]->vbd_id);
#endif /* SHFS_DEBUG */
		hdr_common = (void *)((uint8_t *) chk0 + BOOT_AREA_LENGTH);
		detected_member[nb_detected_members].bd = bd[i];
		memcpy(detected_member[nb_detected_members].uuid, hdr_common->member_uuid, 16);
		nb_detected_members++;
	}
	if (nb_detected_members == 0) {
		ret = -ENOENT;
		goto out_free_chk0;
	}

	/* Load label from first detected member */
	rlen = 4096 / blkdev_ssize(detected_member[0].bd);
	ret = blkdev_sync_read(detected_member[0].bd, 0, rlen, chk0);
	if (ret < 0)
		goto out_free_chk0;
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
			if (memcmp(hdr_common->member[i].uuid, detected_member[m].uuid, 16) == 0) {
				shfs_vol.member[shfs_vol.nb_members].bd = detected_member[m].bd;
				memcpy(shfs_vol.member[shfs_vol.nb_members].uuid, detected_member[m].uuid, 16);
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
		goto out_free_chk0;
	}

	/* chunk and stripe size -> retrieve a device sector factor for each device */
	if (shfs_vol.stripesize > 32768 || shfs_vol.chunksize < 4096 ||
	    !POWER_OF_2(shfs_vol.stripesize)) {
#ifdef SHFS_DEBUG
		printf("Stripe size invalid on volume '%s'\n",
		       shfs_vol.volname);
#endif /* SHFS_DEBUG */
		ret = -ENOENT;
		goto out_free_chk0;
	}
	for (i = 0; i < shfs_vol.nb_members; ++i) {
		shfs_vol.member[i].sfactor = shfs_vol.stripesize / blkdev_ssize(shfs_vol.member[i].bd);
		if (shfs_vol.member[i].sfactor == 0) {
#ifdef SHFS_DEBUG
			printf("Stripe size invalid on volume '%s'\n",
			       shfs_vol.volname);
#endif /* SHFS_DEBUG */
			ret = -ENOENT;
			goto out_free_chk0;
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
			goto out_free_chk0;
		}
	}

	ret = 0;

 out_free_chk0:
	xfree(chk0);
 out:
	return ret;
}

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

static int load_vol_htable(void)
{
	return 0;
}

int mount_shfs(struct blkdev *bd[], unsigned int count)
{
	int ret;

	down(&shfs_mount_lock);

	BUG_ON(shfs_mounted);
	if (count == 0) {
		ret = -EINVAL;
		goto out;
	}

	/* load common volume information */
	ret = load_vol_cconf(bd, count);
	if (ret < 0)
		goto out;
	shfs_mounted = 1;

	/* load vol hash conf (uses shfs_sync_read_chunk) */
	ret = load_vol_hconf();
	if (ret < 0) {
		shfs_mounted = 0;
		goto out;
	}

	/* load htable (uses shfs_sync_read_chunk) */
	ret = load_vol_htable();
	if (ret < 0) {
		shfs_mounted = 0;
		goto out;
	}
	ret = 0;

 out:
	up(&shfs_mount_lock);
	return ret;
}

void umount_shfs(void) {
	down(&shfs_mount_lock);
	shfs_mounted = 0;
	up(&shfs_mount_lock);
}

int shfs_sync_read_chunk(chk_t start, chk_t len, void *buffer)
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
			printf("blkdev_sync_read member=%u, start=%lxs, len=%lus, wptr=0x%p\n",
			       m, start_sec, len_sec, wptr);
#endif /* SHFS_DEBUG */
			ret = blkdev_sync_read(shfs_vol.member[m].bd, start_sec, len_sec, wptr);
			if (ret < 0)
				return ret;
			wptr += shfs_vol.stripesize;
		}
	}

	return 0;
}

void exit_shfs(void) {
}
