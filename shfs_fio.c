/*
 *
 */
#include "shfs_fio.h"
#include "shfs.h"
#include "shfs_htable.h"

static inline __attribute__((always_inline))
struct shfs_bentry *_shfs_lookup_bentry_by_hash(const char *hash)
{
	hash512_t h;
	struct shfs_bentry *bentry;

	if (hash_parse(hash, h, shfs_vol.hlen) < 0)
		return NULL;
	bentry = shfs_btable_lookup(shfs_vol.bt, h);
#ifdef SHFS_MISSSTATS
	if (!bentry) {
		printk("MISS: Element %s is not in cache\n", hash);
	}
#endif
	return bentry;
}

#ifdef SHFS_OPENBYNAME
/*
 * Unfortunately, opening by name ends up in an
 * expensive search algorithm: O(n^2)
 *
 * The next bad thing is, that we need to touch all
 * hentries...
 */
static inline __attribute__((always_inline))
struct shfs_bentry *_shfs_lookup_bentry_by_name(const char *name)
{
	struct shfs_bentry *bentry;
	struct shfs_hentry *hentry;
	unsigned int i;
	size_t name_len;

	name_len = strlen(name);
	for (i = 0; i < shfs_vol.htable_nb_entries; ++i) {
		bentry = shfs_btable_pick(shfs_vol.bt, i);
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
	return NULL;
}
#endif


/*
 * As long as we do not any operation that might call
 * schedule() (e.g., printf()), we do not need to
 * down/up the shfs_mount_lock semaphore -> coop.
 * scheduler
 */
SHFS_FD shfs_fio_open(const char *path)
{
	struct shfs_bentry *bentry;
	struct shfs_hentry *hentry;

	if (!shfs_mounted) {
		errno = ENODEV;
		return NULL;
	}
	if (strlen(path) == 0) {
		errno = ENOENT;
		return NULL;
	}

	/* lookup bentry (either by name or hash) */
	if (path[0] == SFHS_HASH_INDICATOR_PREFIX) {
		bentry = _shfs_lookup_bentry_by_hash(path + 1);
	} else {
#ifdef SHFS_OPENBYNAME
		bentry = _shfs_lookup_bentry_by_name(path);
#else
		bentry = NULL;
#endif
	}
	if (!bentry) {
		errno = ENOENT;
		return NULL;
	}

	/* open hentry */
	hentry = (struct shfs_hentry *)
		((uint8_t *) shfs_vol.htable_chunk_cache[bentry->hentry_htchunk]
		 + bentry->hentry_htoffset);
	if (hentry) {
		shfs_nb_open++;
#ifdef SHFS_HITSTATS
		bentry->ts_laccess = gettimestamp_s();
		bentry->nb_access++;
#endif
        }
	return (SHFS_FD) hentry;
}

void shfs_fio_close(SHFS_FD f)
{
	shfs_nb_open--;
}

void shfs_fio_name(SHFS_FD f, char *out, size_t outlen)
{
	struct shfs_hentry *hentry = (struct shfs_hentry *) f;

	outlen = min(outlen, sizeof(hentry->name) + 1);
	strncpy(out, hentry->name, outlen - 1);
	out[outlen - 1] = '\0';
}

void shfs_fio_mime(SHFS_FD f, char *out, size_t outlen)
{
	struct shfs_hentry *hentry = (struct shfs_hentry *) f;

	outlen = min(outlen, sizeof(hentry->mime) + 1);
	strncpy(out, hentry->mime, outlen - 1);
	out[outlen - 1] = '\0';
}

void shfs_fio_size(SHFS_FD f, uint64_t *out)
{
	struct shfs_hentry *hentry = (struct shfs_hentry *) f;

	*out = hentry->len;
}

void shfs_fio_hash(SHFS_FD f, hash512_t out)
{
	struct shfs_hentry *hentry = (struct shfs_hentry *) f;
	hash_copy(out, hentry->hash, shfs_vol.hlen);
}

/*
 * Slow sync I/O file read function
 * Warning: It is using busy-waiting
 */
int shfs_fio_read(SHFS_FD f, uint64_t offset, void *buf, uint64_t len)
{
	struct shfs_hentry *hentry = (struct shfs_hentry *) f;
	struct mempool_obj *cobj;
	chk_t    chk_off;
	uint64_t byt_off;
	uint64_t buf_off;
	uint64_t left;
	uint64_t rlen;
	int ret = 0;

	/* check boundaries */
	if ((offset > hentry->len) ||
	    ((offset + len) > hentry->len))
		return -EINVAL;

	/* pick chunk I/O buffer from pool */
	cobj = mempool_pick(shfs_vol.chunkpool);
	if (!cobj)
		return -ENOMEM;

	/* perform the I/O chunk-wise */
	chk_off = shfs_volchk_foff(f, offset);
	byt_off = shfs_volchkoff_foff(f, offset);
	left = len;
	buf_off = 0;

	while (left) {
		ret = shfs_read_chunk(chk_off, 1, cobj->data);
		if (ret < 0)
			goto out;

		rlen = min(shfs_vol.chunksize - byt_off, left);
		memcpy((uint8_t *) buf + buf_off,
		       (uint8_t *) cobj->data + byt_off,
		       rlen);
		left -= rlen;

		++chk_off;   /* go to next chunk */
		byt_off = 0; /* byte offset is set on the first chunk only */
		buf_off += rlen;
	}

 out:
	mempool_put(cobj);
	return ret;
}
