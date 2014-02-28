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
	unsigned int id;
	chk_t chunk;                /* addres to entry on vbd / chunk cache */
	off_t offset;
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
 * Serches for a free bucket entry for a hash value
 */
struct shfs_bentry *shfs_btable_getfreeb(struct shfs_btable *bt, hash512_t h);

/**
 * Helpers for hash handling
 */
#define hash_copy(target, source, hlen)	  \
	do { \
		(target).u64[0] = (source).u64[0]; \
		(target).u64[1] = (source).u64[1]; \
		(target).u64[2] = (source).u64[2]; \
		(target).u64[3] = (source).u64[3]; \
		(target).u64[4] = (source).u64[4]; \
		(target).u64[5] = (source).u64[5]; \
		(target).u64[6] = (source).u64[6]; \
		(target).u64[7] = (source).u64[7]; \
	} while(0)

/*
 * Quick compare of two hash values
 * Note that unused fields of hash512_t have to be zero'ed out
 * hlen can be 0 (= 0 bits) until 64 (= 512 bits)
 *
 * Returns 0 if both hashes are equal
 */
static inline int hash_compare(const hash512_t h0, const hash512_t h1, uint8_t hlen)
{
	register unsigned int lidx64;
	register unsigned int ridx64;

	switch (hlen) {
	case 0:
		return 0;
	case 1:
		return (h0.u8[0] != h1.u8[0]); /* 1 byte */
	case 2:
		return (h0.u16[0] != h1.u16[0]); /* 2 bytes */
	case 3 ... 4:
		return (h0.u32[0] != h1.u32[0]); /* 4 bytes */
	case 5 ... 8:
		return (h0.u64[0] != h1.u64[0]); /* 8 bytes */
	default:
		/* quick compare (search starting from both sides to middle) */
		lidx64 = 0;
		ridx64 = (hlen + 7) >> 3; /* fast DIV_ROUND_UP */

		while (lidx64 < ridx64) {
			if (h0.u64[lidx64] != h1.u64[lidx64])
				return 1;
			if (h0.u64[ridx64] != h1.u64[ridx64])
				return 1;
			++lidx64;
			--ridx64;
		}
	}

	return 0;
}

static inline int hash_is_zero(const hash512_t h, uint8_t hlen)
{
	register unsigned int lidx64;
	register unsigned int ridx64;

	switch (hlen) {
	case 0:
		return 0;
	case 1:
		return (h.u8[0] == 0); /* 1 byte */
	case 2:
		return (h.u16[0] == 0); /* 2 bytes */
	case 3 ... 4:
		return (h.u32[0] == 0); /* 4 bytes */
	case 5 ... 8:
		return (h.u64[0] == 0); /* 8 bytes */
	default:
		/* quick compare (search starting from both sides to middle) */
		lidx64 = 0;
		ridx64 = (hlen + 7) >> 3; /* fast DIV_ROUND_UP */

		while (lidx64 < ridx64) {
			if (h.u64[lidx64] != 0)
				return 0;
			if (h.u64[ridx64] != 0)
				return 0;
			++lidx64;
			--ridx64;
		}
	}

	return 1;
}

#endif
