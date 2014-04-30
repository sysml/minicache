/*
 * Simon's HashFS (SHFS) for Mini-OS
 *
 * Copyright(C) 2013-2014 NEC Laboratories Europe. All rights reserved.
 *                        Simon Kuenzer <simon.kuenzer@neclab.eu>
 */
#ifndef _SHFS_DEFS_H_
#define _SHFS_DEFS_H_

#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#ifndef __MINIOS__
#include <uuid/uuid.h>
#include <mhash.h>
#endif /* __MINIOS__ */

typedef uint64_t chk_t;
#ifdef __MINIOS__
typedef uint8_t uuid_t[16];
#endif /* __MINIOS__ */
typedef uint8_t hash512_t[64] __attribute__((aligned(8)));

#define SHFS_MAX_NB_MEMBERS 32

/* vol_byteorder */
#define SBO_LITTLEENDIAN 0
#define SBO_BIGENDIAN    1

/* vol_encoding */
#define SENC_UNSPECIFIED 0

/* allocator */
#define SALLOC_FIRSTFIT   0
#define SALLOC_BESTFIT   1

/* hash function */
#define SHFUNC_SHA       0
#define SHFUNC_MD5       1


/*
 * Helper
 */
#ifndef ALIGN_UP
/* Note: align has to be a power of 2 */
#define ALIGN_UP(size, align)  (((size) + (align) - 1) & ~((align) - 1))
#endif
#ifndef DIV_ROUND_UP
#define DIV_ROUND_UP(num, div) (((num) + (div) - 1) / (div))
#endif
#ifndef POWER_OF_2
#define POWER_OF_2(x)          ((0 != x) && (0 == (x & (x-1))))
#endif
#ifndef min
#define min(a, b) \
    ({ __typeof__ (a) __a = (a); \
       __typeof__ (b) __b = (b); \
       __a < __b ? __a : __b; })
#endif
#ifndef max
#define max(a, b) \
    ({ __typeof__ (a) __a = (a); \
       __typeof__ (b) __b = (b); \
       __a > __b ? __a : __b; })
#endif

/**
 * Common SHFS header
 * (on chunk no. 0)
 * Note: character strings fields are not necessarily null-terminated
 */
#define BOOT_AREA_LENGTH 1024
#define SHFS_MAGIC0 'S'
#define SHFS_MAGIC1 'H'
#define SHFS_MAGIC2 'F'
#define SHFS_MAGIC3 'S'
#define SHFSv1_VERSION1 0x01
#define SHFSv1_VERSION0 0x02

struct shfs_hdr_common {
	uint8_t            magic[4];
	uint8_t            version[2]; /* little endian */
	uuid_t             vol_uuid;
	char               vol_name[16];
	uint8_t            vol_byteorder;
	uint8_t            vol_encoding;
	chk_t              vol_size;
	uint64_t           vol_ts_creation;
	uint32_t           member_stripesize; /* at least 4 KiB (because of first chunk), blkfront can handle at most 32 KiB */
	uint8_t            member_uuid[16]; /* this disk */
	uint8_t            member_count;
	struct {           /* uuid's of all disk members */
		uuid_t    uuid;
	}                  member[16];
} __attribute__((packed));

/**
 * SHFS configuration header
 * (on chunk no. 1)
 */
struct shfs_hdr_config {
	chk_t              htable_ref;
	chk_t              htable_bak_ref; /* if 0 => no backup */
	uint8_t            hfunc;
	uint8_t            hlen; /* num bytes of hash digest, max is 64 (= 512 bits) */
	uint32_t           htable_bucket_count;
	uint32_t           htable_entries_per_bucket;
	uint8_t            allocator;
} __attribute__((packed));

/**
 * SHFS entry (container description)
 * Note: character strings fields are not necessarily null-terminated
 */
struct shfs_hentry {
	hash512_t          hash; /* hash digest */
	chk_t              chunk;
	uint64_t           offset; /* byte offset, usually 0 */
	uint64_t           len; /* length (bytes) */
	char               mime[64]; /* internet media type */
	uint64_t           ts_creation;
	char               name[64];
} __attribute__((packed));

#define CHUNKS_TO_BYTES(chunks, chunksize) ((uint64_t) (chunks) * (uint64_t) (chunksize))

#define SHFS_CHUNKSIZE(hdr_common) ((hdr_common)->member_stripesize * (uint32_t) ((hdr_common)->member_count))
#define SHFS_HENTRY_ALIGN 64 /* has to be a power of 2 */
#define SHFS_HENTRY_SIZE ALIGN_UP(sizeof(struct shfs_hentry), SHFS_HENTRY_ALIGN)
#define SHFS_HENTRIES_PER_CHUNK(chunksize) ((chunksize) / SHFS_HENTRY_SIZE)

#define SHFS_HTABLE_NB_ENTRIES(hdr_config) \
	((hdr_config)->htable_entries_per_bucket * (hdr_config)->htable_bucket_count)
#define SHFS_HTABLE_SIZE_CHUNKS(hdr_config, chunksize) \
	DIV_ROUND_UP(SHFS_HTABLE_NB_ENTRIES((hdr_config)), SHFS_HENTRIES_PER_CHUNK((chunksize)))

#define SHFS_HTABLE_CHUNK_NO(hentry_no, hentries_per_chunk) \
	((hentry_no) / (hentries_per_chunk))
#define SHFS_HTABLE_ENTRY_OFFSET(hentry_no, hentries_per_chunk) \
	(((hentry_no) % (hentries_per_chunk)) * SHFS_HENTRY_SIZE)


#ifdef __MINIOS__
static inline int uuid_compare(const uuid_t uu1, const uuid_t uu2)
{
	return memcmp(uu1, uu2, sizeof(uuid_t));
}

static inline int uuid_is_zero(const uuid_t uu)
{
	unsigned i;
	for (i = 0; i < sizeof(uuid_t); ++i)
		if (uu[i] != 0)
			return 0;
	return 1;
}

static inline int uuid_is_null(const uuid_t uu)
{
	return (uu == NULL);
}

static inline void uuid_copy(uuid_t dst, const uuid_t src)
{
	memcpy(dst, src, sizeof(uuid_t));
}
#endif /* __MINIOS__ */

static inline void hash_copy(hash512_t dst, const hash512_t src, uint8_t hlen)
{
#ifdef __x86_64
	register uint8_t nbleft = hlen & 0x07; /* = mod by 8 */
	register uint64_t mask64;
	register uint64_t *p64_dst;
	register uint64_t *p64_src;
	register uint8_t i;

	for (i = 0; i < hlen; i += 8) {
		p64_dst = (uint64_t *) &dst[i];
		p64_src = (uint64_t *) &src[i];
		*p64_dst = *p64_src;
	}
	if (nbleft) {
		mask64 = (1 << (nbleft << 3)) - 1;
		p64_dst = (uint64_t *) &dst[i];
		p64_src = (uint64_t *) &src[i];
		*p64_dst = *p64_src & mask64;
	}
#else
	memcpy(target, source, hlen);
#endif
}

static inline int hash_compare(const hash512_t h0, const hash512_t h1, uint8_t hlen)
{
#ifdef __x86_64
	register uint8_t nbleft = hlen & 0x07; /* = mod by 8 */
	register uint64_t mask64;
	register uint64_t *p64_0;
	register uint64_t *p64_1;
	register uint8_t i;

	for (i = 0; i < hlen; i += 8) {
		p64_0 = (uint64_t *) &h0[i];
		p64_1 = (uint64_t *) &h1[i];
		if (*p64_0 != *p64_1)
			return 1;
	}
	if (nbleft) {
		mask64 = (1 << (nbleft << 3)) - 1;
		p64_0 = (uint64_t *) &h0[i];
		p64_1 = (uint64_t *) &h1[i];
		if ((*p64_0 & mask64) != (*p64_1 & mask64))
			return 1;
	}

	return 0;
#else
	return (memcmp(h0, h1, hlen) != 0);
#endif
}

static inline int hash_is_zero(const hash512_t h, uint8_t hlen)
{
#ifdef __x86_64
	register uint8_t nbleft = hlen & 0x07; /* = mod by 8 */
	register uint64_t mask64;
	register uint64_t *p64;
	register uint8_t i;

	for (i = 0; i < hlen; i += 8) {
		p64 = (uint64_t *) &h[i];
		if (*p64 != 0)
			return 0;
	}
	if (nbleft) {
		mask64 = (1 << (nbleft << 3)) - 1;
		p64 = (uint64_t *) &h[i];
		if ((*p64 & mask64) != 0)
			return 0;
	}

	return 1;
#else
	uint8_t i;

	for (i = 0; i < hlen; ++i)
		if (h[i] != 0)
			return 0;
	return 1;
#endif
}

static inline void hash_clear(const hash512_t h, uint8_t hlen)
{
#ifdef __x86_64
	register uint64_t *p64;
	register uint8_t i;

	for (i = 0; i < hlen; i += 8) {
		p64 = (uint64_t *) &h[i];
		*p64 = 0;
	}
#else
	memset(h, 0x00, hlen);
#endif
}

static inline int hash_parse(const char *in, hash512_t h, uint8_t hlen)
{
	uint8_t strlen = hlen * 2;
	uint8_t i, nu, nl;

	for (i = 0; i < strlen; ++i) {
		/* get upper nibble (4 bits) */
		switch (in[i]) {
		case '0' ... '9':
			nu = in[i] - '0';
			break;
		case 'a' ... 'f':
			nu = in[i] - 'a' + 10;
			break;
		case 'A' ... 'F':
			nu = in[i] - 'A' + 10;
			break;
		case '\0':
		default:
			return -1; /* unknown character or string ended unexpectedly */
		}

		/* get lower nibble (4 bits) */
		++i;
		switch (in[i]) {
		case '0' ... '9':
			nl = in[i] - '0';
			break;
		case 'a' ... 'f':
			nl = in[i] - 'a' + 10;
			break;
		case 'A' ... 'F':
			nl = in[i] - 'A' + 10;
			break;
		case '\0':
		default:
			return -1;
		}

		h[i >> 1] = (nu << 4) | nl;
	}

	if (in[i] != '\0')
		return -1;

	return 0;
}

static inline uint64_t gettimestamp_s(void)
{
	struct timeval now;
	gettimeofday(&now, NULL);
	return (uint64_t) now.tv_sec;
}

#endif /* _SHFS_DEFS_H_ */
