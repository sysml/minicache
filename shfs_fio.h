#ifndef _SHFS_FIO_
#define _SHFS_FIO_

#include "shfs_defs.h"
#include "shfs.h"
#include "shfs_btable.h"

#ifndef __KERNEL__
#include "shfs_cache.h"
#include "likely.h"

#define SHFS_HASH_INDICATOR_PREFIX '?' /* has to be the same as HTTPURL_ARGS_INDICATOR_PREFIX in http.c */

typedef struct shfs_bentry *SHFS_FD;

/**
 * Opens a file/object via hash string or name depending on
 * the first character of path:
 *
 * Hash: "?024a5bec"
 * Name: "index.html"
 */
SHFS_FD shfs_fio_open(const char *path);
/**
 * Opens a file/object via a hash digest
 */
SHFS_FD shfs_fio_openh(hash512_t h);
/**
 * Creates a file descriptor clone
 */
SHFS_FD shfs_fio_openf(SHFS_FD f);
/**
 * Closes a file descriptor
 */
void shfs_fio_close(SHFS_FD f);

void shfs_fio_name(SHFS_FD f, char *out, size_t outlen); /* null-termination is ensured */
void shfs_fio_hash(SHFS_FD f, hash512_t out);
#define shfs_fio_islink(f) \
	(SHFS_HENTRY_ISLINK((f)->hentry))
void shfs_fio_size(SHFS_FD f, uint64_t *out); /* returns 0 on links */

/**
 * Link object attributes
 * The following interfaces can only be used on link objects
 */
#define shfs_fio_link_type(f) \
	(SHFS_HENTRY_LINK_TYPE((f)->hentry))
#define shfs_fio_link_rport(f) \
	(SHFS_HENTRY_LINKATTR((f)->hentry).rport)
#define shfs_fio_link_rhost(f) \
	(&(SHFS_HENTRY_LINKATTR((f)->hentry).rhost))
void shfs_fio_link_rpath(SHFS_FD f, char *out, size_t outlen); /* null-termination is ensured */

/**
 * File object attributes
 * The following interfaces can only be used to non-link objects
 */
void shfs_fio_mime(SHFS_FD f, char *out, size_t outlen); /* null-termination is ensured */

/* file container size in chunks */
#define shfs_fio_size_chks(f) \
	(DIV_ROUND_UP(((f)->hentry->f_attr.offset + (f)->hentry->f_attr.len), shfs_vol.chunksize))

/* volume chunk address of file chunk address */
#define shfs_volchk_fchk(f, fchk) \
	((f)->hentry->f_attr.chunk + (fchk))

/* volume chunk address of file byte offset */
#define shfs_volchk_foff(f, foff) \
	(((f)->hentry->f_attr.offset + (foff)) / shfs_vol.chunksize + (f)->hentry->f_attr.chunk)
/* byte offset in volume chunk of file byte offset */
#define shfs_volchkoff_foff(f, foff) \
	(((f)->hentry->f_attr.offset + (foff)) % shfs_vol.chunksize)

/* Check macros to test if a address is within file bounds */
#define shfs_is_fchk_in_bound(f, fchk) \
	(shfs_fio_size_chks((f)) > (fchk))
#define shfs_is_foff_in_bound(f, foff) \
	((f)->hentry->f_attr.len > (foff))

/**
 * File cookies
 */
#define shfs_fio_get_cookie(f) \
	((f)->cookie)
static inline int shfs_fio_set_cookie(SHFS_FD f, void *cookie) {
  if (f->cookie)
    return -EBUSY;
  f->cookie = cookie;
  return 0;
}
#define shfs_fio_clear_cookie(f) \
  do { (f)->cookie = NULL; } while (0)

/*
 * Simple but synchronous file read
 * Note: Busy-waiting is used
 */
/* direct read */
int shfs_fio_read(SHFS_FD f, uint64_t offset, void *buf, uint64_t len);
int shfs_fio_read_nosched(SHFS_FD f, uint64_t offset, void *buf, uint64_t len);
/* read is using cache */
int shfs_fio_cache_read(SHFS_FD f, uint64_t offset, void *buf, uint64_t len);
int shfs_fio_cache_read_nosched(SHFS_FD f, uint64_t offset, void *buf, uint64_t len);

/*
 * Async file read
 */
static inline int shfs_fio_cache_aread(SHFS_FD f, chk_t offset, shfs_aiocb_t *cb, void *cb_cookie, void *cb_argp, struct shfs_cache_entry **cce_out, SHFS_AIO_TOKEN **t_out)
{
    register chk_t addr;

    if (unlikely(!(shfs_is_fchk_in_bound(f, offset))))
	return -EINVAL;
    addr = shfs_volchk_fchk(f, offset);
    return shfs_cache_aread(addr, cb, cb_cookie, cb_argp, cce_out, t_out);
}
#endif


#ifdef SHFS_OPENBYNAME
/*
 * Unfortunately, opening by name ends up in an
 * expensive search algorithm: O(n^2)
 */
static inline __attribute__((always_inline))
 struct shfs_bentry *_shfs_lookup_bentry_by_name(const char *name)
{
	struct htable_el *el;
	struct shfs_bentry *bentry;
	struct shfs_hentry *hentry;
	size_t name_len;

	name_len = strlen(name);
	foreach_htable_el(shfs_vol.bt, el) {
		bentry = el->private;
		hentry = (struct shfs_hentry *)
			((uint8_t *) shfs_vol.htable_chunk_cache[bentry->hentry_htchunk]
			 + bentry->hentry_htoffset);

		if (name_len > sizeof(hentry->name))
			continue;

		if (strncmp(name, hentry->name, sizeof(hentry->name)) == 0) {
			/* we found it - hooray! */
			return bentry;
		}
	}

#ifdef SHFS_STATS
	++shfs_vol.mstats.i;
#endif
	return NULL;
}
#endif

static inline __attribute__((always_inline))
struct shfs_bentry *_shfs_lookup_bentry_by_hash(hash512_t h)
{
	struct shfs_bentry *bentry;
#ifdef SHFS_STATS
	struct shfs_el_stats *estats;
#endif

	bentry = shfs_btable_lookup(shfs_vol.bt, h);
#ifdef SHFS_STATS
	if (unlikely(!bentry)) {
		estats = shfs_stats_from_mstats(h);
		if (likely(estats != NULL)) {
			estats->laccess = gettimestamp_s();
			++estats->m;
		}
	}
#endif
	return bentry;
}

#endif /* _SHFS_FIO_ */
