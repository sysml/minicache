/*
 * Simon's HashFS (SHFS) for Mini-OS
 *
 * Copyright(C) 2013-2014 NEC Laboratories Europe. All rights reserved.
 *                        Simon Kuenzer <simon.kuenzer@neclab.eu>
 */
#ifndef _SHFS_HTABLE_H_
#define _SHFS_HTABLE_H_

#include "shfs_defs.h"

/**
 * A bucket entry
 */
struct shfs_bentry {
	hash512_t hash;             /* if zero, this bucket entry is empty */
	chk_t hentry_htchunk;       /* relative chunk:offfset addres to entry in htable */
	off_t hentry_htoffset;
};

/**
 * The bucket table
 */
struct shfs_bucket {
	struct shfs_bentry e[0];
};

/**
 * The bucket table
 */
struct shfs_btable {
	uint32_t nb_buckets;
	uint32_t nb_entries_per_bucket;
	uint8_t hlen;

	struct shfs_bucket *b[0];
};

struct shfs_btable *shfs_alloc_btable(uint32_t nb_buckets, uint32_t nb_entries_per_bucket, uint8_t hash_len);
void shfs_free_btable(struct shfs_btable *bt);

/**
 * Picks a bucket entry by its total index
 */
struct shfs_bentry *shfs_btable_pick(struct shfs_btable *bt, unsigned int bentry_idx);

/**
 * Does a lookup for a bucket entry by its hash value
 */
struct shfs_bentry *shfs_btable_lookup(struct shfs_btable *bt, hash512_t h);

/**
 * Searches for a free bucket entry for a given hash value
 */
struct shfs_bentry *shfs_btable_getfreeb(struct shfs_btable *bt, hash512_t h);

#endif /* _SHFS_HTABLE_H_ */
