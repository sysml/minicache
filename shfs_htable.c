/*
 * Simon's HashFS (SHFS) for Mini-OS
 *
 * Copyright(C) 2013-2014 NEC Laboratories Europe. All rights reserved.
 *                        Simon Kuenzer <simon.kuenzer@neclab.eu>
 */
#ifdef __MINIOS__
#include <mini-os/os.h>
#include <mini-os/types.h>
#include <mini-os/xmalloc.h>
#else
#include <stdlib.h>
#endif

#ifndef CACHELINE_SIZE
#define CACHELINE_SIZE 64
#endif

#include "shfs_htable.h"

struct shfs_btable *shfs_alloc_btable(uint32_t nb_buckets, uint32_t nb_entries_per_bucket, uint8_t hash_len)
{
	size_t bt_size, b_size;
	struct shfs_btable *bt;
	unsigned int i, j;

	bt_size = sizeof(*bt) + (sizeof(void *) * nb_buckets);
#ifdef __MINIOS__
	bt = _xmalloc(bt_size, CACHELINE_SIZE);
#else
	bt = calloc(1, bt_size);
#endif
	if (!bt)
		goto err_out;
#ifdef __MINIOS__
	memset(bt, 0, bt_size);
#endif
	bt->nb_buckets = nb_buckets;
	bt->nb_entries_per_bucket = nb_entries_per_bucket;
	bt->hlen = hash_len;

	/* allocate the buckets */
	b_size = sizeof(struct shfs_bentry) * nb_entries_per_bucket;
	for (i = 0; i < nb_buckets; ++i) {
#ifdef __MINIOS__
		bt->b[i] = _xmalloc(b_size, CACHELINE_SIZE);
#else
		bt->b[i] = calloc(1, b_size);
#endif
		if (!bt->b[i])
			goto err_free_b_ref;

#ifdef __MINIOS__
		memset(bt->b[i], 0, b_size);
#endif
		for (j = 0; j < nb_entries_per_bucket; ++j)
			bt->b[i]->e[j].id = (i * nb_entries_per_bucket) + j;
	}

	return bt;

 err_free_b_ref:
	for (i = 0; i < nb_buckets; ++i) {
		if (bt->b[i]) {
#ifdef __MINIOS__
			xfree(bt->b[i]);
#else
			free(bt->b[i]);
#endif
		}
	}
#ifdef __MINIOS__
	xfree(bt);
#else
	free(bt);
#endif
 err_out:
	return NULL;
}

void shfs_free_btable(struct shfs_btable *bt)
{
	unsigned int i;

	for (i = 0; i < bt->nb_buckets; ++i) {
		if (bt->b[i]) {
#ifdef __MINIOS__
			xfree(bt->b[i]);
#else
			free(bt->b[i]);
#endif
		}
	}
#ifdef __MINIOS__
	xfree(bt);
#else
	free(bt);
#endif
}

/**
 * Retrieve bucket number from hash value
 */
static inline unsigned int _bucket_no(const hash512_t h, uint8_t hlen, uint32_t nb_buckets)
{
	switch (hlen) {
	case 0:
		return 0;
	case 1:
		return (h.u8[0] % nb_buckets); /* 1 byte */
	case 2:
		return (h.u16[0] % nb_buckets); /* 2 byte */
	case 3 ... 4:
		return (h.u32[0] % nb_buckets); /* 4 byte */
	default:
		break;
	}

	/* just take 8 bytes from hash */
	return (h.u64[0] % nb_buckets);
}

struct shfs_bentry *shfs_btable_pick(struct shfs_btable *bt, unsigned int bentry_idx)
{
	unsigned int b_idx;
	unsigned int bucket_idx;

	bucket_idx = bentry_idx / bt->nb_entries_per_bucket;
	b_idx = bentry_idx % bt->nb_entries_per_bucket;

	return &bt->b[bucket_idx]->e[b_idx];
}

struct shfs_bentry *shfs_btable_lookup(struct shfs_btable *bt, hash512_t h)
{
	unsigned int i;
	unsigned int bucket_idx;
	struct shfs_bucket *b;

	bucket_idx = _bucket_no(h, bt->hlen, bt->nb_buckets);
	b = bt->b[bucket_idx];
	for (i = 0; i < bt->nb_entries_per_bucket; ++i) {
		if (hash_compare(b->e[i].hash, h, bt->hlen) == 0) {
			return &b->e[i];
		}
	}

	return NULL; /* no entry found */
}

struct shfs_bentry *shfs_btable_getfreeb(struct shfs_btable *bt, hash512_t h)
{
	unsigned int i;
	unsigned int bucket_idx;
	struct shfs_bucket *b;

	bucket_idx = _bucket_no(h, bt->hlen, bt->nb_buckets);
	b = bt->b[bucket_idx];
	for (i = 0; i < bt->nb_entries_per_bucket; ++i) {
		/* TODO: Check for already existence (preserve unique entries) */
		if (hash_is_zero(b->e[i].hash, bt->hlen)) {
			return &b->e[i];
		}
	}

	return NULL; /* bucket is full, cannot store hash */
}
