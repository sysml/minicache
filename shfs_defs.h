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


/**
 * Common SHFS header
 * (on chunk no. 0)
 */
#define BOOT_AREA_LENGTH 1024
#define SHFS_MAGIC0 'S'
#define SHFS_MAGIC1 'H'
#define SHFS_MAGIC2 'F'
#define SHFS_MAGIC3 'S'
#define SHFSv1_VERSION0 0x1
#define SHFSv1_VERSION1 0x0

/* note: character strings are not necessarily null-terminated */
struct shfs_hdr_common {
	uint8_t            magic[4];
	uint8_t            version[2]; /* little endian */
	uint8_t            vol_uuid[16];
	char               vol_name[16];
	uint8_t            vol_byteorder;
	uint8_t            vol_encoding;
	uint32_t           vol_chunksize; /* at least 4096, max 32 KiB */
	chk_t              vol_size;
	uint64_t           vol_creation_ts;
	uint8_t            member_uuid[16];
	uint8_t            member_count;
	uint32_t           member_stripe_size; /* <= chunksize; chunksize is multiple of it */
	struct {
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
 */
struct shfs_hentry {
	uint64_t           hash[8];
	chk_t              start;
	uint64_t           len; /* in bytes */
	uint64_t           ts_creation;
	uint64_t           ts_laccess;
	uint64_t           access_count;
	char               mime[64];
	char               name[256];
} __attribute__((packed));

/* up aligned hentry => chunksize becomes a multiple of it */
#define SHFS_HENTRY_SIZE(chunksize) ((chunksize) / ((chunksize) / sizeof(struct shfs_hentry)))

#endif /* _SHFS_DEFS_H_ */
