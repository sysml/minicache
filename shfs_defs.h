/*
 * Simon's HashFS (SHFS) for Mini-OS
 *
 * Copyright(C) 2013-2014 NEC Laboratories Europe. All rights reserved.
 *                        Simon Kuenzer <simon.kuenzer@neclab.eu>
 */
#ifndef _SHFS_DEFS_H_
#define _SHFS_DEFS_H_

#include <sys/types.h>
#include <stdint.h>

typedef uint64_t chk_t;

/* vol_byteorder */
#define SBO_LITTLEENDIAN 0
#define SBO_BIGENDIAN    1

/* vol_encoding */
#define SENC_UNSPECIFIED 0

/* allocator */
#define SALLOC_BESTFIT   0

/* hash function */
#define SHFUNC_SHA1      0

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
#define SHFSv1_VERSION0 0x1
#define SHFSv1_VERSION1 0x0

struct shfs_hdr_common {
	uint8_t            magic[4];
	uint8_t            version[2]; /* little endian */
	uint8_t            vol_uuid[16];
	char               vol_name[16];
	uint8_t            vol_byteorder;
	uint8_t            vol_encoding;
	chk_t              vol_size;
	uint64_t           vol_creation_ts;
	uint32_t           member_stripesize; /* at least 4 KiB, at most 32 KiB */
	uint8_t            member_uuid[16]; /* this disk */
	uint8_t            member_count;
	struct {           /* uuid's of all disk members */
		uint8_t    uuid[16];
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
	uint8_t            hlen; /* multiple of 64 bits */
	uint32_t           htable_bucket_count;
	uint32_t           htable_entries_per_bucket;
	uint8_t            allocator;
} __attribute__((packed));

/**
 * SHFS entry (container description)
 * Note: character strings fields are not necessarily null-terminated
 */
struct shfs_hentry {
	uint64_t           hash[8]; /* 512 bits */
	chk_t              chunk;
	uint32_t           offset; /* byte offset, usually 0 */
	uint64_t           len; /* length (bytes) */
	char               mime[128]; /* internet media type */
	uint64_t           ts_creation;
	uint64_t           ts_laccess;
	uint64_t           access_count;
	char               name[256];
} __attribute__((packed));

#define BYTES_TO_CHUNKS(bytes,  chunksize) DIV_ROUND_UP((bytes), (chunksize))
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

#endif /* _SHFS_DEFS_H_ */
