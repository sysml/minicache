/*
 * Simple HashFS (SHFS) for Mini-OS
 *
 * Copyright(C) 2013-2014 NEC Laboratories Europe. All rights reserved.
 *                        Simon Kuenzer <simon.kuenzer@neclab.eu>
 *
 * This file implements the hash-table based file table
 * It is basically a wrapper for htable.c/.h
 */
#ifndef _SHFS_BTABLE_H_
#define _SHFS_BTABLE_H_

#ifndef __MINIOS__
#include <assert.h>

#ifndef ASSERT
#define ASSERT assert
#endif
#else /* __MINIOS__ */
#include <mini-os/lib.h>
#endif /* __MINIOS__ */

#include "shfs_defs.h"
#include "htable.h"

#ifdef SHFS_STATS
#include "shfs_stats_data.h"
#endif

#ifndef CACHELINE_SIZE
#define CACHELINE_SIZE 64
#endif

/*
 * Bucket entry that points to
 * the depending hentry (SHFS Hash Table Entry)
 */
struct shfs_bentry {
	chk_t hentry_htchunk;       /* relative chunk:offfset addres to entry in SHFS htable */
	off_t hentry_htoffset;
	struct shfs_hentry *hentry; /* reference to buffered entry in cache */

	unsigned int refcount;
#ifdef SHFS_STATS
	struct shfs_el_stats hstats;
#endif /* SHFS_STATS */
};

#define shfs_alloc_btable(nb_bkts, ent_per_bkt, hlen) \
	alloc_htable((nb_bkts), (ent_per_bkt), (hlen), sizeof(struct shfs_bentry), CACHELINE_SIZE);
#define shfs_free_btable(bt) \
	free_htable((bt))

/**
 * Does a lookup for a bucket entry by its hash value
 */
static inline struct shfs_bentry *shfs_btable_lookup(struct htable *bt, hash512_t h) {
	struct htable_el *el;

	el = htable_lookup(bt, h);
	if (el)
		return (struct shfs_bentry *) el->private;
	return NULL;
}

/**
 * Searches and allocates an according bucket entry for a given hash value
 */
static inline struct shfs_bentry *shfs_btable_addentry(struct htable *bt, hash512_t h) {
	struct htable_el *el;

	el = htable_add(bt, h);
	if (el)
		return (struct shfs_bentry *) el->private;
	return NULL;
}

#define shfs_btable_rmentry(bt, h) \
	htable_rm((bt), (h))

/**
 * This function is intended to be used during mount time.
 * It is intended to load a hash table from a device:
 * It Picks a bucket entry by its total index of the hash table,
 * overwrites its hash value and links the element to the end of the table list.
 * The functions returns the according shfs_bentry so that this data structure
 * can be filled-in with further meta data
 *
 * Note: Ensure that the hash table (*bt) is cleared before you start 'feeding' it
 */
static inline struct shfs_bentry *shfs_btable_feed(struct htable *bt, uint64_t ent_idx, hash512_t h) {
	uint32_t bkt_idx;
	uint32_t el_idx_bkt;
	struct htable_bkt *b;
	struct htable_el *el;

	/* TODO: Check for overflows */
	bkt_idx = (uint32_t) (ent_idx / (uint64_t) bt->el_per_bkt);
	el_idx_bkt = (uint32_t) (ent_idx % (uint64_t) bt->el_per_bkt);
	ASSERT(bkt_idx < bt->nb_bkts);

	/* entry found */
	b = bt->b[bkt_idx];
	ASSERT(hash_is_zero(b->h[el_idx_bkt], bt->hlen));
	el = _htable_bkt_el(b, el_idx_bkt);

	/* overwrite hash value */
	hash_copy(b->h[el_idx_bkt], h, bt->hlen);

	/* link the element */
	if (!hash_is_zero(h, bt->hlen)) {
		if (!bt->head) {
			bt->head = el;
			bt->tail = el;
			el->prev = NULL;
			el->next = NULL;
		} else {
			bt->tail->next = el;
			el->prev = bt->tail;
			el->next = NULL;
			bt->tail = el;
		}
	}

	return (struct shfs_bentry *) el->private;
}

#endif /* _SHFS_BTABLE_H_ */
