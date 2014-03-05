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

	if (hash_parse(hash, h, shfs_vol.hlen) < 0)
		return NULL;
	return shfs_btable_lookup(shfs_vol.bt, h);
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
	size_t strcmp_len;
	size_t name_len;

	name_len = strlen(name);
	for (i = 0; i < shfs_vol.htable_nb_entries; ++i) {
		bentry = shfs_btable_pick(shfs_vol.bt, i);
		hentry = (struct shfs_hentry *)
			((uint8_t *) shfs_vol.htable_chunk_cache[bentry->hentry_htchunk]
			 + bentry->hentry_htoffset);

		strcmp_len = min(name_len, sizeof(hentry->name));
		if (strncmp(name, hentry->name, strcmp_len) == 0) {
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
	if (path[0] == '?') {
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
	if (hentry)
		shfs_nb_open++;
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
 * Prototypical... it is using sync I/O (it's slow, I know)
 */
int shfs_fio_read(SHFS_FD f, uint64_t offset, void *buf, uint64_t len)
{
	struct shfs_hentry *hentry = (struct shfs_hentry *) f;
	struct mempool_obj *cobj;
	chk_t    chk_off;
	uint64_t byt_off;
	uint64_t left;
	uint64_t rlen;
	int ret = 0;

	/* check boundaries */
	if ((offset > hentry->len) ||
	    ((offset + len) > hentry->len))
		return -EINVAL;

	/* pick chunk I/O buffer from pool */
	cobj = mempool_pick(shfs_vol.chunkpool);
	while (!cobj) {
		schedule(); /* wait for another thread releasing a buffer */
		cobj = mempool_pick(shfs_vol.chunkpool);
	}

	/* perform the I/O chunk-wise */
	chk_off = (hentry->offset + offset) / shfs_vol.chunksize +
		  hentry->chunk;
	byt_off = (hentry->offset + offset) % shfs_vol.chunksize;
	left = len;

	while (left) {
		ret = shfs_sync_read_chunk(chk_off, 1, cobj->data);
		if (ret < 0)
			goto out;

		rlen = min(shfs_vol.chunksize - byt_off, left);
		memcpy(buf, (uint8_t *) cobj->data + byt_off, rlen);
		left -= rlen;

		++chk_off;   /* go to next chunk */
		byt_off = 0; /* byte offset is set on the first chunk only */
	}

 out:
	mempool_put(cobj);
	return ret;
}
