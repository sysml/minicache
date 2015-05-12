
/*
 * Simple memory pool implementation for MiniOS
 *
 * Copyright(C) 2013 NEC Laboratories Europe. All rights reserved.
 *                   Simon Kuenzer <simon.kuenzer@neclab.eu>
 */
#include <target/sys.h>
#include <errno.h>
#include <mempool.h>

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

static inline uint32_t log2(uint32_t v)
{
  uint32_t i = 0;

  while (v) {
	v >>= 1;
	i++;
  }
  return (i - 1);
}

/* Return size, increased to alignment with align. Copied from xmalloc.c */
static inline size_t align_up(size_t size, size_t align)
{
  return (size + align - 1) & ~(align - 1);
}

struct mempool *alloc_mempool(uint32_t nb_objs, size_t obj_size, size_t obj_data_align, size_t obj_headroom, size_t obj_tailroom, void (*obj_init_func)(struct mempool_obj *, void *), void *obj_init_func_argp, size_t obj_private_len)
{
  struct mempool *p = NULL;
  struct mempool_obj *o_ptr;
  uintptr_t o_offset;
  size_t h_size ,o_size;
  size_t o_data_offset;
  size_t struct_mempool_size, struct_mempool_obj_size;
  uint32_t i;

  if (obj_data_align)
	ASSERT(POWER_OF_2(obj_data_align));

  obj_private_len         = align_up(obj_private_len, MIN_ALIGN);
  struct_mempool_size     = align_up(sizeof(struct mempool), MIN_ALIGN);
  struct_mempool_obj_size = align_up(sizeof(struct mempool_obj), MIN_ALIGN);
  obj_headroom            = align_up(obj_headroom, MIN_ALIGN);
  obj_data_align          = max(obj_data_align, MIN_ALIGN);

  /* calculate size of mempool header */
  h_size = align_up(struct_mempool_size, obj_data_align);
  o_data_offset = struct_mempool_obj_size + obj_private_len + obj_headroom;
  /* add initial padding to header to move beginning of obj->data of the first pool object to alignment */
  h_size = align_up(h_size + o_data_offset, obj_data_align) - o_data_offset;

  /* calculate final object size */
  o_size =  struct_mempool_obj_size;
  o_size += obj_private_len;
  o_size += obj_headroom;
  o_size += obj_size;
  o_size += obj_tailroom;
  /* add padding to objects to keep beginning of object data area aligned for all subsequent objects */
  o_size = align_up(o_size, obj_data_align);

  /* allocate pool */
  p = target_malloc(max(PAGE_SIZE, obj_data_align), h_size + (o_size * nb_objs));
  if (!p) {
	errno = ENOMEM;
	goto error;
  }

  /* setup meta data */
  p->nb_objs            = nb_objs;
  p->obj_size           = obj_size;
  p->obj_headroom       = obj_headroom;
  p->obj_tailroom       = obj_tailroom;
  p->obj_data_offset    = o_data_offset; /* default offset of obj_data to the base of the object */
  p->obj_private_len    = obj_private_len;
  p->obj_init_func      = obj_init_func;
  p->obj_init_func_argp = obj_init_func_argp;

  /* initialize pool management */
  p->free_objs = alloc_ring(1 << (log2(nb_objs) + 1));
  if (!p->free_objs)
	goto error_free_p;

  /* initialize object skeletons and add them to pool management */
  o_offset = (uintptr_t) p + h_size;
  for (i = 0; i < nb_objs; i++) {
	o_ptr           = (struct mempool_obj *) (o_offset + (i * o_size));
	o_ptr->p_ref    = p;
	if (obj_private_len)
	  o_ptr->private = (void *)((uintptr_t) o_ptr + struct_mempool_obj_size);
	else
	  o_ptr->private = NULL;

	ring_enqueue(p->free_objs, o_ptr); /* never fails */
  }

#ifdef MEMPOOL_DEBUG
  /*
   * Prints a memory pool allocation summary
   */
  printf("memory pool resides at %p with %llu kbytes for %llu objects (object size: %llu B->%llu B; object data alignment: %llu B)\n", p, (h_size + (o_size * nb_objs)) / 1024, nb_objs, obj_size, o_size, obj_data_align);
  printf("pool management ring resides at %p and can hold %llu object references\n", p->free_objs, p->free_objs->size);
  printf("                      +--------------------+\n");
  printf(             "%018p -> |   struct mempool   | 0x%06llx\n", p, struct_mempool_size);
  if(h_size - struct_mempool_size)
	printf("                      | / / / / / / / / / /| 0x%06llx\n", h_size - struct_mempool_size);

  for (i = 0; i<nb_objs; i++){
	o_ptr = (struct mempool_obj *)(o_offset + (i * o_size));
	o_ptr->data = (void *)((uintptr_t) o_ptr + p->obj_data_offset);
	printf("                      +--------------------+\n", o_ptr);
	printf(             "%018p -> | struct mempool_obj | 0x%06llx\n", o_ptr, struct_mempool_obj_size);
	if (p->obj_private_len)
	  printf(             "%018p -> |    obj_private     | 0x%06llx\n", o_ptr->private, p->obj_private_len);
	if (p->obj_headroom) {
	  printf("                      |- - - - - - - - - - |\n");
	  printf(             "%018p -> |      HEADROOM      | 0x%06llx\n", (void *)((uintptr_t) o_ptr->data - p->obj_headroom), p->obj_headroom);
	}
	printf("                      |- - - - - - - - - - |\n");
	printf(             "%018p -> |       OBJECT       | 0x%06llx\n", o_ptr->data, p->obj_size);
	if (p->obj_tailroom) {
	  printf("                      |- - - - - - - - - - |\n");
	  printf(             "%018p -> |      TAILROOM      | 0x%06llx\n", (void *)((uintptr_t) o_ptr->data + p->obj_size), p->obj_tailroom);
	}
	if (o_size - p->obj_tailroom - p->obj_size - p->obj_headroom - p->obj_private_len - struct_mempool_obj_size)
	  printf("                      | / / / / / / / / / /| 0x%06llx\n", o_size - p->obj_tailroom - p->obj_size - p->obj_headroom - p->obj_private_len - struct_mempool_obj_size);
  }
  printf("                      +--------------------+\n");
#endif /* MEMPOOL_DEBUG */

  return p;

 error_free_p:
  target_free(p);
 error:
  return NULL;
}

void free_mempool(struct mempool *p)
{
  if (p) {
	BUG_ON(ring_count(p->free_objs) != p->nb_objs); /* some objects of this pool may be still in use */
	free_ring(p->free_objs);
	target_free(p);
  }
}
