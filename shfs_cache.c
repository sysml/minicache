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

#define shfs_cache_notify_retry() \
	do { \
		if (unlikely(!shfs_vol.chunkcache->_in_cb_retry && \
		             shfs_vol.chunkcache->call_cb_retry && \
		             shfs_vol.chunkcache->cb_retry)) { \
			dprintf("Notify retry of failed AIO request setup...\n"); \
			shfs_vol.chunkcache->call_cb_retry = 0; \
			shfs_vol.chunkcache->_in_cb_retry = 1; \
			shfs_vol.chunkcache->cb_retry(); \
			shfs_vol.chunkcache->_in_cb_retry = 0; \
		} \
	} while(0)

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

int shfs_alloc_cache(uint32_t nb_bffs, uint8_t ht_order, void (*cb_retry)(void))
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
    cc->nb_ref_entries = 0;
    cc->cb_retry = cb_retry;
    cc->call_cb_retry = 0;
    cc->_in_cb_retry = 0;

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
static inline void shfs_cache_flush_alist(void)
{
    struct shfs_cache_entry *cce;
    int orig_call_cb_retry = shfs_vol.chunkcache->call_cb_retry;

    dprintf("Flushing cache...\n");
    while (cce = dlist_first_el(shfs_vol.chunkcache->alist, struct shfs_cache_entry)) {
	    if (cce->t) {
		    dprintf("I/O of chunk buffer %llu is not done yet, "
		            "waiting for completion...\n", cce->addr);
		    /* set refcount to 1 in order to avoid freeing of an invalid
		     * buffer by aiocb */
		    cce->refcount = 1;
		    /* disable retry notification call */
		    shfs_vol.chunkcache->call_cb_retry = 0;

		     /* wait for I/O without having thread switching
		      * because otherwise, the state of alist might change */
		    while (cce->t)
			    shfs_poll_blkdevs(); /* requires shfs_mounted = 1 */

		    cce->refcount = 0; /* retore refcount */

		    /* since we come back from an I/O we should schedule
		     * an I/O retry call */
		    orig_call_cb_retry = 1;
	    }

	    dprintf("Releasing chunk buffer %llu...\n", cce->addr);
	    shfs_cache_unlink(cce); /* unlinks element from alist and clist */
	    mempool_put(cce->pobj);
    }

    /* reenable previous state of retry notification call */
    shfs_vol.chunkcache->call_cb_retry = orig_call_cb_retry;
}

void shfs_flush_cache(void)
{
    shfs_cache_flush_alist();
    shfs_cache_notify_retry();
}

void shfs_free_cache(void)
{
    shfs_cache_flush_alist();
    free_mempool(shfs_vol.chunkcache->pool); /* will fail with an assertion
                                              * if objects were not put back to the pool already */
    xfree(shfs_vol.chunkcache);
    shfs_vol.chunkcache = NULL;
}

static void _cce_aiocb(SHFS_AIO_TOKEN *t, void *cookie, void *argp)
{
    struct shfs_cache_entry *cce = (struct shfs_cache_entry *) cookie;
    SHFS_AIO_TOKEN *t_cur, *t_next;
    int ret;

    BUG_ON(cce->refcount == 0 && cce->aio_chain.first);
    BUG_ON(t != cce->t);

    ret = shfs_aio_finalize(t);
    cce->t = NULL;
    cce->invalid = (ret < 0) ? 1 : 0;

    /* I/O failed and no references? (in case of read-ahead) */
    if (unlikely(cce->refcount == 0 && cce->invalid)) {
	shfs_cache_unlink(cce);
	mempool_put(cce->pobj);
        dprintf("Destroyed failed cache I/O at chunk %llu: %d\n", cce->addr, ret);
        goto out;
    }

    /* clear chain */
    t_cur = cce->aio_chain.first;
    cce->aio_chain.first = NULL;
    cce->aio_chain.last = NULL;

    /* call registered callbacks (AIO_TOKEN emulation) */
    while (t_cur) {
	dprintf("Notify child token (chunk %llu): %p\n", cce->addr, t_cur);
	t_next = t_cur->_next;
	t_cur->ret = ret;
	t_cur->infly = 0;
	if (t_cur->cb) {
	    /* Call child callback */
	    t_cur->cb(t_cur, t_cur->cb_cookie, t_cur->cb_argp);
	}
	t_cur = t_next;
    }

 out:
    shfs_cache_notify_retry();
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
	/* try to pick a buffer (that has completed I/O) from the available list */
	dlist_foreach(cce, shfs_vol.chunkcache->alist, alist) {
		if (cce->t == NULL)
			goto found;
	}
	/* we are out of buffers */
	errno = EAGAIN;
	return NULL;

    found:
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
	    mempool_put(cce->pobj);
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

    ASSERT(cce_out != NULL);
    ASSERT(t_out != NULL);

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
	    if (errno == EAGAIN)
		    shfs_vol.chunkcache->call_cb_retry = 1;
	    goto err_out;
	}
    }

    /* increase refcount */
    if (cce->refcount == 0) {
	dlist_unlink(cce, shfs_vol.chunkcache->alist, alist);
	++shfs_vol.chunkcache->nb_ref_entries;
    }
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
    t = shfs_aio_pick_token();
    if (unlikely(!t)) {
	dprintf("Failed to append AIO token: Out of token\n");
	shfs_vol.chunkcache->call_cb_retry = 1; /* note that callback will be called */
	ret = -EAGAIN;
	goto err_dec_refcount;
    }
    t->cb = cb;
    t->cb_cookie = cb_cookie;
    t->cb_argp = cb_argp;
    t->infly = 1; /* mark token as "busy" */
    if (cce->aio_chain.last) {
	    cce->aio_chain.last->_next = t;
	    t->_prev = cce->aio_chain.last;
    } else {
	    cce->aio_chain.first = t;
	    t->_prev = NULL;
    }
    t->_next = NULL;
    cce->aio_chain.last = t;
    *t_out = t;
    *cce_out = cce;
    return 1;

 err_dec_refcount:
    --cce->refcount;
    if (cce->refcount == 0) {
	--shfs_vol.chunkcache->nb_ref_entries;
	dlist_append(cce, shfs_vol.chunkcache->alist, alist);
	/* because we are out of AIO token it does not make sense to not notify
	 * others for retry: There is indeed a buffer free'd but no I/O operation
	 * can be done so far and on this buffer an I/O operation is in fly */
    }
 err_out:
    *t_out = NULL;
    *cce_out = NULL;
    return ret;
}

/*
 * Fast version to release a cache buffer,
 * however, the I/O needs to be completed on the buffer
 */
void shfs_cache_release(struct shfs_cache_entry *cce)
{
    dprintf("Release cache of chunk %llu (refcount=%u, caller=%p)\n", cce->addr, cce->refcount, get_caller());
    BUG_ON(cce->refcount == 0);
    BUG_ON(!shfs_aio_is_done(cce->t));

    --cce->refcount;
    if (cce->refcount == 0) {
	--shfs_vol.chunkcache->nb_ref_entries;
	if (likely(!cce->invalid)) {
	    dlist_append(cce, shfs_vol.chunkcache->alist, alist);
	} else {
            dprintf("Destroy invalid cache of chunk %llu\n", cce->addr);
	    shfs_cache_unlink(cce);
            mempool_put(cce->pobj);
	}

	shfs_cache_notify_retry();
    }
}

/*
 * Release a cache buffer (like shfs_cache_release)
 * but also cancels an incomplete I/O request
 * The corresponding AIO token is released
 */
void shfs_cache_release_ioabort(struct shfs_cache_entry *cce, SHFS_AIO_TOKEN *t)
{
    dprintf("Release cache of chunk %llu (refcount=%u, caller=%p)\n", cce->addr, cce->refcount, get_caller());
    BUG_ON(cce->refcount == 0);
    BUG_ON(!shfs_aio_is_done(cce->t) && t == NULL);
    BUG_ON(shfs_aio_is_done(cce->t) && !shfs_aio_is_done(t));

    if (!shfs_aio_is_done(t)) {
	    /* unlink token from AIO notification chain */
	    dprintf(" \\_ Abort AIO token %p\n", t);
	    if (t->_prev)
		t->_prev->_next = t->_next;
	    else
		cce->aio_chain.first = t->_next;
	    if (t->_next)
		t->_next->_prev = t->_prev;
	    else
		cce->aio_chain.last = t->_prev;
    }
    if (t) {
	    /* release token */
	    shfs_aio_put_token(t);
    }

    /* decrease refcount */
    --cce->refcount;
    if (cce->refcount == 0) {
	--shfs_vol.chunkcache->nb_ref_entries;
	if (likely(!cce->invalid)) {
	    dlist_append(cce, shfs_vol.chunkcache->alist, alist);
	} else {
            dprintf("Destroy invalid cache of chunk %llu\n", cce->addr);
	    shfs_cache_unlink(cce);
            mempool_put(cce->pobj);
	}
    }

    /* notify retry if cache buffer can be reused/was released or the AIO token was released */
    if (t || (shfs_aio_is_done(cce->t) && cce->refcount==0))
	shfs_cache_notify_retry();
}

#ifdef SHFS_CACHE_STATS_DISPLAY
int shcmd_shfs_cache_stats(FILE *cio, int argc, char *argv[])
{
	uint32_t i;
	struct shfs_cache_entry *cce;

	if (!shfs_mounted) {
		fprintf(cio, "Filesystem is not mounted\n");
		return -1;
	}

	printk("Number of referenced cache buffers: %3u\n", shfs_vol.chunkcache->nb_ref_entries);
	printk("Buffer states:\n");
	for (i = 0; i < shfs_vol.chunkcache->htlen; ++i) {
		dlist_foreach(cce, shfs_vol.chunkcache->htable[i].clist, clist) {
			printk(" ht[%2u] chk:%8llu, refcount:%3u, %s\n",
			       i,
			       cce->addr,
			       cce->refcount,
			       cce->invalid ? "INVALID" : "valid");
		}
	}

	fprintf(cio, "Stats dumped to system output\n");
	return 0;
}
#endif
