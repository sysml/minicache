#include <mini-os/os.h>
#include <mini-os/types.h>
#include <mini-os/xmalloc.h>

#include "shfs_cache.h"
#include "likely.h"

#if (defined SHFS_CACHE_DEBUG || defined SHFS_DEBUG)
#define ENABLE_DEBUG
#endif
#include "debug.h"

#define MIN_ALIGN 8

static void _cce_pobj_init(struct mempool_obj *pobj, void *unused)
{
    struct shfs_cache_entry *cce = pobj->private;

    cce->pobj = pobj;
    cce->refcount = 0;
    cce->buffer = pobj->data;
    cce->invalid = 1; /* buffer is not ready yet */

    cce->t = NULL;
    cce->aio_chain.first = NULL;
    cce->aio_chain.last = NULL;
}

int shfs_alloc_cache(uint32_t nb_bffs, uint8_t ht_order)
{
    struct shfs_cache *cc;
    uint32_t htlen, i;
    size_t cc_size;
    int ret;

    ASSERT(shfs_vol.chunkcache == NULL);
    ASSERT(ht_order > 0 && ht_order < 32);

    htlen = (1 << ht_order);
    cc_size = sizeof(*cc) + (htlen * sizeof(struct shfs_cache_htel));
    cc = _xmalloc(cc_size, MIN_ALIGN);
    if (!cc) {
	    ret = -ENOMEM;
	    goto err_out;
    }
    cc->pool = alloc_mempool(nb_bffs, shfs_vol.chunksize, shfs_vol.ioalign, 0, 0,
                             _cce_pobj_init, NULL, sizeof(struct shfs_cache_entry));
    if (!cc->pool) {
	    ret = -ENOMEM;
	    goto err_free_cc;
    }
    dlist_init_head(cc->alist);
    for (i = 0; i < htlen; ++i) {
	    dlist_init_head(cc->htable[i].clist);
	    cc->htable[i].len = 0;
    }
    cc->htlen = htlen;
    cc->htmask = htlen - 1;

    shfs_vol.chunkcache = cc;
    return 0;

 err_free_cc:
    xfree(cc);
 err_out:
    return ret;
}

#define shfs_cache_htindex(addr) \
	(((uint32_t) (addr)) & (shfs_vol.chunkcache->htmask))

static inline struct shfs_cache_entry *shfs_cache_find(chk_t addr)
{
    struct shfs_cache_entry *cce;
    register uint32_t i = shfs_cache_htindex(addr);

    dlist_foreach(cce, shfs_vol.chunkcache->htable[i].clist, clist) {
        if (cce->addr == addr)
            return cce;
    }
    return NULL; /* not found */
}

/* removes a cache entry from the cache */
static inline void shfs_cache_unlink(struct shfs_cache_entry *cce)
{
    register uint32_t i;

    ASSERT(cce->refcount == 0);

    i = shfs_cache_htindex(cce->addr);
    /* unlink element from hash table collision list */
    dlist_unlink(cce, shfs_vol.chunkcache->htable[i].clist, clist);
    /* unlink element from available list */
    dlist_unlink(cce, shfs_vol.chunkcache->alist, alist);
}

/* put unreferenced buffers back to the pool */
void shfs_flush_cache(void)
{
    struct shfs_cache_entry *cce;

    ASSERT(shfs_mounted);

    /* TODO: Proper release of memory
     * (because next pointer should not be accessed after the memory got release) */
    dlist_foreach(cce, shfs_vol.chunkcache->alist, alist) {
	/* release object from cache */
	shfs_cache_unlink(cce);
        /* release buffer */
        mempool_put(cce->pobj);
    }
}

void shfs_free_cache(void)
{
    shfs_flush_cache();
    free_mempool(shfs_vol.chunkcache->pool); /* will fail with an assertion
                                              * if objects were not put back to the pool already */
    xfree(shfs_vol.chunkcache);
}

static void _cce_aiocb(SHFS_AIO_TOKEN *t, void *cookie, void *argp)
{
    struct shfs_cache_entry *cce = (struct shfs_cache_entry *) cookie;
    SHFS_AIO_TOKEN *t_cur, *t_next;
    int ret;

    ret = shfs_aio_finalize(t);
    cce->invalid = (ret < 0) ? 1 : 0;

    /* I/O failed and no references? (in case of read-ahead) */
    if (unlikely(cce->refcount == 0 && cce->invalid)) {
	shfs_cache_unlink(cce);
	mempool_put(cce->pobj);
        dprintf("Destroyed failed cache I/O at chunk %llu: %d\n", cce->addr, ret);
	return;
    }

    /* call registered callbacks (AIO_TOKEN emulation) */
    t_cur = cce->aio_chain.first;
    while (t_cur) {
        dprintf("Notify child token: %p\n", t_cur);
	t_next = t_cur->_next;
	t_cur->ret = ret;
	t_cur->infly = 0;
	if (t_cur->cb) {
	    /* Call child callback */
	    t_cur->cb(t_cur, t_cur->cb_cookie, t_cur->cb_argp);
	}
	t_cur = t_next;
    }

    /* clear chain */
    cce->aio_chain.first = NULL;
    cce->aio_chain.last = NULL;
}

static inline struct shfs_cache_entry *shfs_cache_add(chk_t addr)
{
    struct mempool_obj *cce_obj;
    struct shfs_cache_entry *cce;
    register uint32_t i;

    cce_obj = mempool_pick(shfs_vol.chunkcache->pool);
    if (cce_obj) {
	/* got a new buffer: append it to alist */
	cce = cce_obj->private;
	dlist_append(cce, shfs_vol.chunkcache->alist, alist);
    } else {
	/* try to pick a buffer from the available list */
	if (unlikely(dlist_is_empty(shfs_vol.chunkcache->alist))) {
		/* we are out of buffers */
		errno = ENOBUFS;
		return NULL;
	}
	cce = dlist_first_el(shfs_vol.chunkcache->alist, struct shfs_cache_entry);
	/* unlink from hash table */
	i = shfs_cache_htindex(cce->addr);
	dlist_unlink(cce, shfs_vol.chunkcache->htable[i].clist, clist);
	/* move entry to the tail of alist */
	dlist_relink_tail(cce, shfs_vol.chunkcache->alist, alist);
    }

    cce->addr = addr;
    cce->t = shfs_aread_chunk(addr, 1, cce->buffer,
                              _cce_aiocb, cce, NULL);
    if (unlikely(!cce->t)) {
	    dlist_unlink(cce, shfs_vol.chunkcache->alist, alist);
	    mempool_put(cce_obj);
	    dprintf("Could not initiate I/O request for chunk %llu: %d\n", addr, errno);
	    return NULL;
    }

    /* link element to hash table */
    i = shfs_cache_htindex(addr);
    dlist_append(cce, shfs_vol.chunkcache->htable[i].clist, clist);

    return cce;
}

int shfs_cache_aread(chk_t addr, shfs_aiocb_t *cb, void *cb_cookie, void *cb_argp, struct shfs_cache_entry **cce_out, SHFS_AIO_TOKEN **t_out)
{
    struct shfs_cache_entry *cce;
    SHFS_AIO_TOKEN *t;
    int ret;

    /* sanity checks */
    if (unlikely(!shfs_mounted)) {
        ret = -ENODEV;
        goto err_out;
    }
    if (unlikely(addr == 0 || addr > shfs_vol.volsize)) {
        ret = -EINVAL;
        goto err_out;
    }

    /* check if we cahced already this request */
    cce = shfs_cache_find(addr);
    if (!cce) {
        /* no -> initiate a new I/O request */
        dprintf("Try to adding chunk %llu to cache\n", addr);
	cce = shfs_cache_add(addr);
	if (!cce) {
	    ret = -errno;
	    goto err_out;
	}
    }

    /* increase refcount */
    if (cce->refcount == 0)
	dlist_unlink(cce, shfs_vol.chunkcache->alist, alist);
    ++cce->refcount;

    /* I/O of element done already? */
    if (likely(shfs_aio_is_done(cce->t))) {
        dprintf("Chunk %llu found in cache and it is ready\n", addr);
        *t_out = NULL;
        *cce_out = cce;
        return 0;
    }

    /* chain a new AIO token for caller (emulates async I/O) */
    dprintf("Chunk %llu found in cache but it is not ready yet: Appending AIO token\n", addr);
    t = shfs_aio_pick_token(cb, cb_cookie, cb_argp);
    if (unlikely(!t)) {
	dprintf("Failed to append AIO token: Out of token\n");
	ret = -EAGAIN;
	goto err_dec_refcount;
    }
    t->infly = 1; /* mark child token as "busy" */
    t->_next = NULL;
    if (cce->aio_chain.last)
	    cce->aio_chain.last->_next = t;
    else
	    cce->aio_chain.first = t;
    cce->aio_chain.last = t;

    *t_out = t;
    *cce_out = cce;
    return 1;

 err_dec_refcount:
    shfs_cache_release(cce);
 err_out:
    return ret;
}

void shfs_cache_release(struct shfs_cache_entry *cce)
{
    ASSERT(cce->refcount > 0);

    --cce->refcount;
    dprintf("Cache of chunk %llu released (refcount=%u)\n", cce->addr, cce->refcount);
    if (cce->refcount == 0) {
	if (likely(!cce->invalid) || !shfs_aio_is_done(cce->t)) {
	    dlist_append(cce, shfs_vol.chunkcache->alist, alist);
	} else {
            dprintf("Destroying invalid cache of chunk %llu\n", cce->addr);
	    shfs_cache_unlink(cce);
            mempool_put(cce->pobj);
	}
    }
}
