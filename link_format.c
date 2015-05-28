#include "link_format.h"

enum lftype mime_to_lftype(const char *mime) {
	enum lftype ret;

	/* TODO: returned type is fixed type for now (independent of mime) */
	ret = LFT_RAW512;

	return ret;
}

int init_lformat(struct lfstate *lfs, enum lftype type, size_t offset)
{
	/* TODO: supported type is fixed for now */
	if (type != LFT_RAW512)
		return -EINVAL;
  
	lfs->type = type;
	lfs->pos  = offset;
	lfs->joins.num = 0;
	lfs->joins.head = 0;
	return 0;
}

#define _lformat_add_join(lfs, off) \
	do { \
		if ((lfs)->joins.num)								\
			(lfs)->joins.head = ((lfs)->joins.head + 1)  % (LF_MAXNB_JOINS);	\
		else										\
			(lfs)->joins.head = 0;							\
		if ((lfs)->joins.num < (LF_MAXNB_JOINS))					\
			++(lfs)->joins.num;							\
		(lfs)->joins.offset[(lfs)->joins.head] = (off);				\
	} while(0)

int lformat_parse(struct lfstate *lfs, const char *b, size_t len)
{
	size_t next;

	lfs->pos += len;

	switch(lfs->type) {
	case LFT_RAW512:
		next = lformat_getrjoin(lfs) + 512;
		while (next < lfs->pos) {
			_lformat_add_join(lfs, next);
			next += 512;
		}
		break;

	default: /* unsupported type */
		break;
	}

	return 0;
}
