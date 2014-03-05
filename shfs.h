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
#include "blkdev.h"

#include "shfs_defs.h"

#define MAX_NB_TRY_BLKDEVS 64

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
 * Slow I/O: sequential sync I/O for volume chunks
 * These functions are intended to be used during mount/umount time
 * because they can run without calling shfs_poll_blkdevs() frequently
 */
int shfs_sync_io_chunk(chk_t start, chk_t len, int write, void *buffer);
#define shfs_sync_read_chunk(start, len, buffer) \
	shfs_sync_io_chunk((start), (len), 0, (buffer))
#define shfs_sync_write_chunk(start, len, buffer) \
	shfs_sync_io_chunk((start), (len), 1, (buffer))

#endif /* _SHFS_H_ */
