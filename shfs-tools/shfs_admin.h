/*
 *
 */
#ifndef _SHFS_MKFS_
#define _SHFS_MKFS_

#include "tools_common.h"
#include "shfs_defs.h"

#define STR_VERSION "Simon's HashFS Tools: Admin v0.01"

#define MAX_NB_TRY_BLKDEVS SHFS_MAX_NB_MEMBERS

enum action {
	NONE = 0,
	ADDFILE,
	RMFILE,
	DUMP
};

struct job {
	struct job *next;

	enum action action;
	char *path;
};

struct args {
	char **devpath;
	unsigned int nb_devs;

	struct job *jobs; /* list of jobs */
};

struct vol_member {
	struct disk *d;
	uuid_t uuid;
};

/* Copy from ../shfs.h */
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
	chk_t htable_ref;
	chk_t htable_bak_ref;
	chk_t htable_len;
	uint32_t htable_nb_buckets;
	uint32_t htable_nb_entries;
	uint32_t htable_nb_entries_per_bucket;
	uint32_t htable_nb_entries_per_chunk;
	uint8_t hlen;
};


#endif /* _SHFS_MKFS_ */
