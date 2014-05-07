#include "shfs_stats.h"
#include "shfs.h"
#include "htable.h"

int shfs_init_mstats(uint32_t nb_bkts, uint32_t ent_per_bkt, uint8_t hlen)
{
	shfs_vol.mstats.el_ht = alloc_htable(nb_bkts, ent_per_bkt, hlen,
	                                     sizeof(struct shfs_el_stats), 0);
	if (!shfs_vol.mstats.el_ht)
		return -errno;
	shfs_vol.mstats.i = 0;
	shfs_vol.mstats.e = 0;

	return 0;
}

void shfs_free_mstats(void)
{
	free_htable(shfs_vol.mstats.el_ht);
}

int shfs_dump_mstats(shfs_dump_el_stats_t dump_el, void *dump_el_argp) {
	int ret;
	struct htable_el *el;

	foreach_htable_el(shfs_vol.mstats.el_ht, el) {
		ret = dump_el(dump_el_argp, *el->h, 0,
		              (struct shfs_el_stats *) el->private);
		if (ret < 0)
			return ret;
	}

	return 0;
}

int shfs_dump_hstats(shfs_dump_el_stats_t dump_el, void *dump_el_argp) {
	int ret;
	struct htable_el *el;

	foreach_htable_el(shfs_vol.bt, el) {
		ret = dump_el(dump_el_argp, *el->h, 1,
		              shfs_stats_from_bentry((struct shfs_bentry *) el->private));
		if (ret < 0)
			return ret;
	}

	return 0;
}
