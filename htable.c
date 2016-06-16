/*
 * Simple hash table implementation for MiniOS and POSIX
 *
 * Copyright(C) 2013-204 NEC Laboratories Europe. All rights reserved.
 *                       Simon Kuenzer <simon.kuenzer@neclab.eu>
 */
#include <target/sys.h>
#if defined(__MINIOS__)
#include <mini-os/os.h>
#include <mini-os/types.h>
#include <mini-os/xmalloc.h>
#elif defined(__KERNEL__)
#include <linux/types.h>
#include <target/stubs.h>
#else
#include <stdlib.h>
#include <asm/bug.h>
#include <string.h>
#endif

#ifndef MIN_ALIGN
#define MIN_ALIGN ((size_t) 8)
#endif

#include "htable.h"

#ifndef max
#define max(a, b) \
    ({ __typeof__ (a) __a = (a); \
       __typeof__ (b) __b = (b); \
       __a > __b ? __a : __b; })
#endif

static inline size_t align_up(size_t size, size_t align)
{
  return (size + align - 1) & ~(align - 1);
}

struct htable *alloc_htable(uint32_t nb_bkts, uint32_t el_per_bkt, uint8_t hlen, size_t el_private_len, size_t align)
{
	size_t ht_size;
	size_t bkt_hdr_size;
	size_t bkt_size;
	size_t el_hdr_size;
	size_t el_size;
	struct htable *ht;
	struct htable_bkt *bkt;
	struct htable_el *el;
	uint32_t i, j;

	align = max(MIN_ALIGN, align);

	el_hdr_size  = align_up(sizeof(struct htable_el), align);
	el_size      = el_hdr_size + align_up(el_private_len, align);
	bkt_hdr_size = align_up(sizeof(struct htable_bkt)
	               + (sizeof(hash512_t) * el_per_bkt), align); /* hash list */
	bkt_size     = bkt_hdr_size
		       + (el_size * el_per_bkt) /* element list */;
	ht_size      = sizeof(struct htable)
		       + sizeof(struct htable_bkt *) * nb_bkts;

#ifdef HTABLE_DEBUG
	printf("el_size  = %lu B\n", el_size);
	printf("bkt_size = %lu B\n", bkt_size);
	printf("ht_size  = %lu B\n", ht_size);
#endif
	/* allocate main htable struct */
	ht = target_malloc(align, ht_size);
	if (!ht) {
		errno = ENOMEM;
		goto err_out;
	}
	memset(ht, 0, ht_size);

#ifdef HTABLE_DEBUG
	printf("htable (%lu B) @ %p\n", ht_size);
#endif
	ht->nb_bkts = nb_bkts;
	ht->el_per_bkt = el_per_bkt;
	ht->hlen = hlen;
	ht->head = NULL;
	ht->tail = NULL;

	/* allocate buckets */
	for (i = 0; i < nb_bkts; ++i) {
		bkt = target_malloc(align, bkt_size);
		if (!bkt) {
			errno = ENOMEM;
			goto err_free_bkts;
		}
		memset(bkt, 0, bkt_size);

#ifdef HTABLE_DEBUG
		printf(" bucket %lu (%lu B) @ %p\n", i, bkt_size, bkt);
#endif
		ht->b[i] = bkt;
		bkt->el = (void *) (((uint8_t *) ht->b[i]) + bkt_hdr_size);
		bkt->el_size = el_size;
		bkt->el_private_len = el_private_len;

		for (j = 0; j < el_per_bkt; ++j) {
			el = _htable_bkt_el(bkt, j);
			el->h = &bkt->h[j];
			el->private = (void *) (((uint8_t *) el) + el_hdr_size);

#ifdef HTABLE_DEBUG
			//printf("  entry %3lu:%02lu (%p): h = @%p; private = @%p\n",
			//        i, j, el, el->h, el->private);
#endif
		}
	}

	return ht;

 err_free_bkts:
	for (i = 0; i < nb_bkts; ++i) {
		if (ht->b[i]) {
			target_free(ht->b[i]);
		}
	}
	target_free(ht);
 err_out:
	return NULL;
}

void free_htable(struct htable *ht)
{
	uint32_t i;

	for (i = 0; i < ht->nb_bkts; ++i) {
		if (ht->b[i]) {
			target_free(ht->b[i]);
		}
	}
	target_free(ht);
}
