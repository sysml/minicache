/*
 * Simple memory pool implementation for MiniOS
 *
 * Copyright(C) 2013 NEC Laboratories Europe. All rights reserved.
 *                   Simon Kuenzer <simon.kuenzer@neclab.eu>
 */
#ifndef _MEMPOOL_H_
#define _MEMPOOL_H_

#include <stdint.h>
#include <errno.h>
#include <ring.h>

#include "likely.h"

/*
 * MEMPOOL OBJECT: MEMORY LAYOUT
 *
 *          ++--------------------++
 *          || struct mempool_obj ||
 *          ||                    ||
 *          || - -private area- - ||
 *          ++--------------------++\
 *          |      HEAD ROOM       | |
 *          |   ^              ^   |  > lhr
 * *data ->/+---|--------------|---+/
 *        | |                      |
 *   len <  |     OBJECT           |
 *        | |     DATA AREA        |
 *        | |                      |
 *         \+---|--------------|---+\
 *          |   v              v   | |
 *          |      TAIL ROOM       |  > ltr
 *          +----------------------+/
 *
 * Object data area can be increased afterwards by using the space of
 * the object's head- and tailroom (e.g., for packet encapsulation)
 *
 * If an align is passed to the memory pool allocator, the beginning of
 * the object data area (regardingless to head- and tailroom) will be aligned.
 */
struct mempool_obj {
  struct mempool *p_ref; /* ptr to depending mempool (DO NOT CHANGE!) */
  size_t lhr;            /* left headroom space */
  size_t ltr;            /* left tailroom space */
  size_t len;            /* length of data area */
  void *data;            /* ptr to data area */
  void *private;         /* ptr to private meta data area (DO NOT CHANGE!) */
};

/*
 * MEMPOOL MEMORY: LAYOUT
 *
 *          ++--------------------++\
 *          ||   struct mempool   || |
 *          ||                    ||  > h_size
 *          ++--------------------++ |
 *          |    // initial //     | |
 *          |    // padding //     | |
 *          +======================+/\
 *          |       OBJECT 1       |  |
 *          +----------------------+   > o_size
 *          | // padding in obj // |  |
 *          +======================+ /
 *          |       OBJECT 2       |
 *          +----------------------+
 *          | // padding in obj // |
 *          +======================+
 *          |       OBJECT 3       |
 *          +----------------------+
 *          | // padding in obj // |
 *          +======================+
 *          |         ...          |
 *          v                      v
 */
struct mempool {
  uint32_t nb_objs;
  size_t obj_size;
  size_t obj_headroom;
  size_t obj_tailroom;
  size_t obj_data_offset;
  size_t obj_private_len;
  void (*obj_init_func)(struct mempool_obj *, void *);
  void *obj_init_func_argp;
  struct ring *free_objs;
};

/*
 * Callback obj_init_func will be called while objects are picked from this memory pool
 *  void obj_init_func(struct mempool_obj *obj, void *argp)
 */
struct mempool *alloc_mempool(uint32_t nb_objs, size_t obj_size, size_t obj_data_align, size_t obj_headroom, size_t obj_tailroom, void (*obj_init_func)(struct mempool_obj *, void *), void *obj_init_func_argp, size_t obj_private_len);
#define alloc_simple_mempool(nb_objs, obj_size) alloc_mempool((nb_objs), (obj_size), 0, 0, 0, NULL, NULL, 0)
void free_mempool(struct mempool *p);

/*
 * Pick an object from a memory pool
 * Returns NULL on failure
 */
static inline struct mempool_obj *mempool_pick(struct mempool *p)
{
  struct mempool_obj *obj;
  obj = ring_dequeue(p->free_objs);
  if (unlikely(!obj))
	return NULL;

  /* initialize object size */
  obj->len = p->obj_size;
  obj->lhr = p->obj_headroom;
  obj->ltr = p->obj_tailroom;
  obj->data = (void *)((uintptr_t) obj + p->obj_data_offset);
  if (p->obj_init_func)
	p->obj_init_func(obj, p->obj_init_func_argp);
  return obj;
}

/*
 * Returns 0 on success, -1 on failure
 */
static inline int mempool_pick_multiple(struct mempool *p, struct mempool_obj *objs[], uint32_t count)
{
  uint32_t i;

  if (unlikely(ring_dequeue_multiple(p->free_objs, (void **) objs, count) < 0))
	return -1;

  for (i=0; i<count; i++) {
	/* initialize object size */
	objs[i]->len = p->obj_size;
	objs[i]->lhr = p->obj_headroom;
	objs[i]->ltr = p->obj_tailroom;
	objs[i]->data = (void *)((uintptr_t) objs[i] + p->obj_data_offset);
	if (p->obj_init_func)
	  p->obj_init_func(objs[i], p->obj_init_func_argp);
  }
  return 0;
}

#define mempool_free_count(p) ring_count((p)->free_objs)

/*
 * Put an object back to its depending memory pool.
 * This is like free() for memory pool objects
 */
//#define mempool_put(obj) ring_enqueue((obj)->p_ref->free_objs, obj);
static inline void mempool_put(struct mempool_obj *obj)
{
  ring_enqueue(obj->p_ref->free_objs, obj); /* never fails on right usage because pool's ring can hold all of it's object references */
}

/*
 * Caution: Use this function only if you are sure that all objects were picked from the same memory pool!
 *          Otherwise, you have to use mempool_put for each object
 */
static inline void mempool_put_multiple(struct mempool_obj *objs[], uint32_t count)
{
  if (likely(count > 0))
	ring_enqueue_multiple(objs[0]->p_ref->free_objs, (void **) objs, count);
}

/*
 * Caution: This function does not check if object resizing is safe
 */
static inline void mempool_obj_prepend_nocheck(struct mempool_obj *obj, ssize_t len)
{
  obj->lhr -= len;
  obj->len += len;
  obj->data = (void *)((uintptr_t) obj->data - len);
}

/*
 * Caution: This function does not check if object resizing is safe
 */
static inline void mempool_obj_append_nocheck(struct mempool_obj *obj, ssize_t len)
{
  obj->ltr -= len;
  obj->len += len;
}

/*
 * Returns 0 on success, -1 on failure
 */
static inline int mempool_obj_prepend(struct mempool_obj *obj, ssize_t len)
{
  if (unlikely(len > obj->lhr || (len < 0 && (-len) > obj->len))) {
	errno = ENOSPC;
	return -1;
  }
  mempool_obj_prepend_nocheck(obj, len);
  return 0;
}

/*
 * Returns 0 on success, -1 on failure
 */
static inline int mempool_obj_append(struct mempool_obj *obj, ssize_t len)
{
  if (unlikely(len > obj->ltr || (len < 0 && (-len) > obj->len))) {
	errno = ENOSPC;
	return -1;
  }
  mempool_obj_append_nocheck(obj, len);
  return 0;
}

/*
 * NOTE:
 * Using the famous container_of() macro does not work with structs
 * defined in the data area of these memory pool objects. This is
 * because obj->data is a reference to the head of your struct
 * that is located in the data field. It is not the head of the
 * struct itself.
 *
 * If you need to back reference to the memory pool container,
 * it is recommended to add reference to it in your struct definition.
 */
#endif /* _MEMPOOL_H_ */
