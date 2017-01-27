/*
 * Simple memory pool implementation for MiniOS
 *
 * Copyright(C) 2013 NEC Laboratories Europe. All rights reserved.
 *                   Simon Kuenzer <simon.kuenzer@neclab.eu>
 */
#include <target/sys.h>
#include <errno.h>

#include "mempool.h"

#ifdef MEMPOOL_DEBUG
#define ENABLE_DEBUG
#endif
#include "debug.h"

#define MIN_ALIGN 8 /* minimum alignment of data structures within the mempool (64-bits) */

#ifndef max
#define max(a, b) \
    ({ __typeof__ (a) __a = (a); \
       __typeof__ (b) __b = (b); \
       __a > __b ? __a : __b; })
#endif
#ifndef POWER_OF_2
  #define POWER_OF_2(x)   ((0 != x) && (0 == (x & (x-1))))
#endif

/* Return size, increased to alignment with align. Copied from xmalloc.c */
static inline size_t align_up(size_t size, size_t align)
{
  return (size + align - 1) & ~(align - 1);
}

struct mempool *alloc_enhanced_mempool(uint32_t nb_objs,
					 size_t obj_size, size_t obj_data_align, size_t obj_headroom, size_t obj_tailroom, size_t obj_private_len, int sep_obj_data,
					 void (*obj_init_func)(struct mempool_obj *, void *), void *obj_init_func_argp,
					 void (*obj_pick_func)(struct mempool_obj *, void *), void *obj_pick_func_argp,
					 void (*obj_put_func)(struct mempool_obj *, void *), void *obj_put_func_argp)
{
  struct mempool *p;
  struct mempool_obj *obj;
  size_t h_size, p_size, m_size, o_size;
  size_t pool_size, data_size;
  uint32_t i;

  if (obj_data_align)
	ASSERT(POWER_OF_2(obj_data_align));
  obj_data_align = max(obj_data_align, MIN_ALIGN);

  printd("ALLOC:"
         " nb_objs = %"PRIu32","
         " obj_size = %"PRIu64","
         " obj_data_align = %"PRIu64","
         " obj_headroom = %"PRIu64","
         " obj_tailroom = %"PRIu64","
         " obj_private_len = %"PRIu64","
         " sep_obj_data = %s\n",
	 nb_objs,
	 obj_size,
	 (uint64_t) obj_data_align,
	 (uint64_t) obj_headroom,
	 (uint64_t) obj_tailroom,
	 (uint64_t) obj_private_len,
	 sep_obj_data ? "TRUE" : "FALSE");

  /* calculate private data sizes */
  h_size         = sizeof(struct mempool); /* header length  */
  m_size         = align_up(sizeof(struct mempool_obj), MIN_ALIGN);
  p_size         = m_size + obj_private_len; /* private length */

  /* calculate object sizes */
  if (sep_obj_data) {
    obj_headroom = align_up(obj_headroom, obj_data_align);
    o_size       = align_up(obj_headroom + obj_size + obj_tailroom, obj_data_align);
    obj_tailroom = o_size - obj_headroom - obj_size;
  } else {
    obj_headroom = align_up(p_size + obj_headroom, obj_data_align) - p_size;
    o_size       = align_up(p_size + obj_headroom + obj_size + obj_tailroom, obj_data_align);
    obj_tailroom = o_size - obj_headroom - obj_size - p_size;
  }

  /* allocate memory */
  if (sep_obj_data) {
    h_size = align_up(h_size, MIN_ALIGN);
    p_size = align_up(p_size, MIN_ALIGN);
    o_size = align_up(o_size, obj_data_align);
    pool_size = h_size + nb_objs * p_size;
    data_size = nb_objs * o_size;

    p = target_malloc(MIN_ALIGN, pool_size);
    if (!p) {
        errno = ENOMEM;
        goto error;
    }
    p->obj_data_area = target_malloc(obj_data_align, data_size);
    if (!p) {
        errno = ENOMEM;
        goto error_free_p;
    }
  } else {
    h_size = align_up(h_size, obj_data_align);
    o_size = align_up(o_size, obj_data_align);
    pool_size = h_size + nb_objs * o_size;
    data_size = 0;

    p = target_malloc(obj_data_align, pool_size);
    if (!p) {
        errno = ENOMEM;
        goto error;
    }
    p->obj_data_area = NULL; /* no extra object data area*/
  }

  /* initialize pool management */
  p->nb_objs            = nb_objs;
  p->nb_free_objs       = nb_objs;
  p->obj_size           = obj_size;
  p->pool_size          = pool_size + data_size;
  p->obj_headroom       = obj_headroom;
  p->obj_tailroom       = obj_tailroom;
  p->obj_pick_func      = obj_pick_func;
  p->obj_pick_func_argp = obj_pick_func_argp;
  p->obj_put_func       = obj_put_func;
  p->obj_put_func_argp  = obj_put_func_argp;
  dlist_init_head(p->free_objs);

  printd("pool @ %p, len: %"PRIu64":\n"
         "  nb_objs:             %"PRIu32"\n"
         "  obj_size:            %"PRIu64"\n"
         "  obj_headroom:        %"PRIu64"\n"
         "  obj_tailroom:        %"PRIu64"\n"
         "  obj_data_area:       %p (len: %"PRIu64")\n",
         p, pool_size,
         p->nb_objs,
         p->obj_size,
         p->obj_headroom,
         p->obj_tailroom,
         p->obj_data_area,
         data_size);

  /* initialize objects and add them to pool management */
  for (i = 0, obj = (struct mempool_obj *)(((uintptr_t) p) + h_size);
       i < nb_objs;
       ++i,   obj = (struct mempool_obj *)(((uintptr_t) obj) + (sep_obj_data ? (p_size) : (o_size)))) {
    obj->p_ref = p;

    if (sep_obj_data)
      obj->base  = (void *) (((uintptr_t) p->obj_data_area) + i * o_size);
    else
      obj->base  = (void *) (((uintptr_t) obj) + p_size);

    if (obj_private_len)
      obj->private = (void *) (((uintptr_t) obj) + m_size);
    else
      obj->private = NULL;

    mempool_reset_obj(obj);

    if (obj_init_func)
      obj_init_func(obj, obj_init_func_argp);

    dlist_append(obj, p->free_objs, flst);

#ifdef ENABLE_DEBUG
    if (i < 3) { /* in order to avoid flooding: print details only of first three objects */
      printd("obj%"PRIu32" @ %p:\n"
             "  p_ref:               %p\n"
             "  private:             %p (len: %"PRIu64")\n"
             "  base:                %p\n"
             "  left bytes headroom: %"PRIu64"\n"
             "  data:                %p (len: %"PRIu64")\n"
             "  left bytes tailroom: %"PRIu64"\n",
             i, obj,
             obj->p_ref,
             obj->private,
             (uint64_t) (m_size + obj_private_len),
             obj->base,
             (uint64_t) obj->lhr,
             obj->data,
             (uint64_t) obj->len,
             (uint64_t) obj->ltr);
    }
    if (i == 3)
             printd("etc\n");
#endif
  }

  return p;

 error_free_p:
  target_free(p);
 error:
  return NULL;
}

struct mempool *alloc_enhanced_mempool2(size_t pool_size,
					 size_t obj_size, size_t obj_data_align, size_t obj_headroom, size_t obj_tailroom, size_t obj_private_len, int sep_obj_data,
					 void (*obj_init_func)(struct mempool_obj *, void *), void *obj_init_func_argp,
					 void (*obj_pick_func)(struct mempool_obj *, void *), void *obj_pick_func_argp,
					 void (*obj_put_func)(struct mempool_obj *, void *), void *obj_put_func_argp)
{
  size_t h_size, p_size, m_size, o_size;
  uint32_t nb_objs = 0;

  /* calculate private data sizes */
  h_size         = sizeof(struct mempool); /* header length  */
  m_size         = align_up(sizeof(struct mempool_obj), MIN_ALIGN);
  p_size         = m_size + obj_private_len; /* private length */

  if (pool_size < h_size) {
    errno = EINVAL;
    return NULL;
  }
  pool_size   -= h_size;

  /* calculate object sizes */
  if (sep_obj_data) {
    obj_headroom = align_up(obj_headroom, obj_data_align);
    o_size       = align_up(obj_headroom + obj_size + obj_tailroom, obj_data_align);
    obj_tailroom = o_size - obj_headroom - obj_size;

    /* convert pool_size -> nb_objs */
    nb_objs      = pool_size / (p_size + o_size + sizeof(void *));
  } else {
    obj_headroom = align_up(p_size + obj_headroom, obj_data_align) - p_size;
    o_size       = align_up(p_size + obj_headroom + obj_size + obj_tailroom, obj_data_align);
    obj_tailroom = o_size - obj_headroom - obj_size - p_size;

    /* convert pool_size -> nb_objs */
    nb_objs      = pool_size / (o_size + sizeof(void *));
  }

  return alloc_enhanced_mempool(nb_objs, obj_size, obj_data_align, obj_headroom, obj_tailroom, obj_private_len, sep_obj_data,
				obj_init_func, obj_init_func_argp, obj_pick_func, obj_pick_func_argp, obj_put_func, obj_put_func_argp);
}

void free_mempool(struct mempool *p)
{
  if (p) {
	BUG_ON(p->nb_free_objs != p->nb_objs); /* some objects of this pool may be still in use */
	if (p->obj_data_area)
	  target_free(p->obj_data_area);
	target_free(p);
  }
}
