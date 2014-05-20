/*
 * Statistics extension for SHFS
 */
#ifndef _SHFS_STATS_H_
#define _SHFS_STATS_H_

#include "shfs_stats_data.h"
#include "shfs_btable.h"
#include "shfs_fio.h"
#include "shfs.h"
#include "likely.h"
#include "ctldir.h"

/*
 * Retrieve stats structure from SHFS btable entry
 */
#define shfs_stats_from_bentry(bentry) \
	(&((bentry)->hstats))

/*
 * Retrieves stats structure from an SHFS_FD
 * NOTE: No NULL check is made since it is assumed that
 * f is provided by the currently mounted shfs hash table
 * -> bentry does exist
 */
static inline struct shfs_el_stats *shfs_stats_from_fd(SHFS_FD f) {
	struct shfs_bentry *bentry = (struct shfs_bentry *) f;

	return shfs_stats_from_bentry(bentry);
}

/*
 * Retrieves stats element from miss stats table
 * NOTE: A new entry is created automatically, if it does not
 * exist yet
 */
static inline struct shfs_el_stats *shfs_stats_from_mstats(hash512_t h) {
	int is_new;
	struct htable_el *el;
	struct shfs_el_stats *el_stats;
#if defined SHFS_STATS_HTTP && defined SHFS_STATS_HTTP_DPC
	register unsigned int i;
#endif

	el = htable_lookup_add(shfs_vol.mstats.el_ht, h, &is_new);
	if (unlikely(!el))
		return NULL;

	el_stats = (struct shfs_el_stats *) el->private;
	if (is_new) {
		el_stats->laccess = 0;
		el_stats->h = 0;
		el_stats->m = 0;
#ifdef SHFS_STATS_HTTP
		el_stats->c = 0;
#ifdef SHFS_STATS_HTTP_DPC
		for (i=0; i<SHFS_STATS_HTTP_DPCR; ++i)
			el_stats->p[i] = 0;
#endif
#endif
	}
	return el_stats;
}

/*
 * Resetting statistics
 */
static inline void shfs_reset_mstats(void) {
	htable_clear(shfs_vol.mstats.el_ht);
	shfs_vol.mstats.i = 0;
	shfs_vol.mstats.e = 0;
}

static inline void shfs_reset_hstats(void) {
	struct htable_el *el;
	struct shfs_el_stats *el_stats;
#if defined SHFS_STATS_HTTP && defined SHFS_STATS_HTTP_DPC
	register unsigned int i;
#endif

	foreach_htable_el(shfs_vol.bt, el) {
		el_stats = shfs_stats_from_bentry((struct shfs_bentry *) el->private);
		el_stats->laccess = 0;
		el_stats->h = 0;
		el_stats->m = 0;
#ifdef SHFS_STATS_HTTP
		el_stats->c = 0;
#ifdef SHFS_STATS_HTTP_DPC
		for (i=0; i<SHFS_STATS_HTTP_DPCR; ++i)
			el_stats->p[i] = 0;
#endif
#endif
	}
}

#define shfs_reset_stats() \
	do { \
		shfs_reset_hstats(); \
		shfs_reset_mstats(); \
	} while (0)

/*
 * Dumps statistics of element entries
 */
typedef int (*shfs_dump_el_stats_t)(void *argp, hash512_t h, int loaded, struct shfs_el_stats *stats);

int shfs_dump_mstats(shfs_dump_el_stats_t dump_el, void *dump_el_argp);
int shfs_dump_hstats(shfs_dump_el_stats_t dump_el, void *dump_el_argp);

static inline int shfs_dump_stats(shfs_dump_el_stats_t dump_el, void *dump_el_argp)
{
	int ret;
	ret = shfs_dump_hstats(dump_el, dump_el_argp);
	if (unlikely(ret < 0))
		return ret;
	ret = shfs_dump_mstats(dump_el, dump_el_argp);
	if (unlikely(ret < 0))
		return ret;
	return 0;
}

/*
 * Tools to display/export stats via uSh/ctldir
 */
int init_shfs_stats_export(unsigned int vbd_id);
int register_shfs_stats_tools(struct ctldir *cd);
void exit_shfs_stats_export(void);

#endif /* _SHFS_STATS_H_ */
