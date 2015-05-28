#ifndef _LINK_FORMAT_H_
#define _LINK_FORMAT_H_

#include <stddef.h>
#include <inttypes.h>
#include <errno.h>

#define LF_MAXNB_JOINS 2 /* keep two recent join offsets */

enum lftype {
	LFT_UNKNOWN = 0,
	LFT_RAW512
};

struct lfstate {
	enum lftype type;

	/* state of parser */
	size_t offset;
	size_t pos;

	/* list of n recent join points */
	struct {
		size_t offset[LF_MAXNB_JOINS];
		unsigned int head;
		unsigned int num;
	} joins;
};

enum lftype mime_to_lftype(const char *mime);
int init_lformat(struct lfstate *lfs, enum lftype type, size_t offset);
int lformat_parse(struct lfstate *lfs, const char *b, size_t len);

static inline size_t lformat_getjoin(struct lfstate *lfs, unsigned idx)
{
	unsigned int p;

	/* index is outside of parser window?
	 * -> return initial offset */
	if (idx > lfs->joins.num)
		return lfs->offset;

	p = (idx > lfs->joins.head) ?
	  (LF_MAXNB_JOINS - (idx - lfs->joins.head)) :
	  lfs->joins.head - idx;
	return lfs->joins.offset[p];
}
/* most recent join */
#define lformat_getrjoin(lfs) \
  lformat_getjoin((lfs), 0)
/* oldest join in parser window */
#define lformat_getojoin(lfs) \
  lformat_getjoin((lfs), ((lfs)->num ? ((lfs)->num - 1) : 0))

#endif /* _LINK_FORMAT_H_ */
