#ifndef _SHFS_FIO_
#define _SHFS_FIO_

#include "shfs_defs.h"
#include "shfs.h"

#define SFHS_HASH_INDICATOR_PREFIX '?'

typedef struct shfs_hentry *SHFS_FD;

/**
 * Opens a file/object via hash or name depending on
 * the first character of path:
 *
 * Hash: "?024a5bec"
 * Name: "index.html"
 */
SHFS_FD shfs_fio_open(const char *path);
void shfs_fio_close(SHFS_FD f);

/**
 * File/object information
 */
void shfs_fio_mime(SHFS_FD f, char *out, size_t outlen); /* null-termination is ensured */
void shfs_fio_name(SHFS_FD f, char *out, size_t outlen); /* null-termination is ensured */
void shfs_fio_hash(SHFS_FD f, hash512_t out);
void shfs_fio_size(SHFS_FD f, uint64_t *out);

/* volume chunk address of file chunk address */
#define shfs_volchk_fchk(f, fchk) \
	((f)->chunk + (fchk))

/* volume chunk address of file byte offset */
#define shfs_volchk_foff(f, foff) \
	(((f)->offset + (foff)) / shfs_vol.chunksize + (f)->chunk)
/* byte offset in volume chunk of file byte offset */
#define shfs_volchkoff_foff(f, foff) \
	(((f)->offset + (foff)) % shfs_vol.chunksize)

/* Check macros to test if a address is within file bounds */
#define shfs_is_fchk_in_bound(f, fchk) \
	(DIV_ROUND_UP(((f)->offset + (f)->len), shfs_vol.chunksize) > (fchk))
#define shfs_is_foff_in_bound(f, foff) \
	((f)->len > (foff))


/*
 * Synchronous file read
 * Note: Busy-waiting is used
 */
int shfs_fio_read(SHFS_FD f, uint64_t offset, void *buf, uint64_t len);

#endif /* _SHFS_FIO_ */
