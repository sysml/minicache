/*
 * Statistics extension for SHFS
 */
#ifndef _SHFS_STATS_DATA_H_
#define _SHFS_STATS_DATA_H_

#include "htable.h"

struct shfs_mstats {
	uint64_t i; /* invalid requests */
	uint64_t e; /* errors */
	struct htable *el_ht; /* hash table of elements that are not in cache */
};

struct shfs_el_stats {
	uint64_t laccess; /* last access timestamp */
	uint64_t h; /* element hit */
	uint64_t m; /* element miss */
#ifdef SHFS_STATS_HTTP
	uint64_t f; /* completed full file transfer */
	uint64_t p; /* completed partial file transfer */
#endif
};

int shfs_init_mstats(uint32_t nb_bkts, uint32_t ent_per_bkt, uint8_t hlen);
void shfs_free_mstats(void);

#endif
