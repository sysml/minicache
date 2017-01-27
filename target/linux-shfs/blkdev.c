#include "shfs.h"
#include <linux/pagemap.h>

static inline int read_one_page(struct shfs_sb_info *sbi, sector_t start, char *buffer)
{
	struct address_space *mapping = sbi->sb->s_bdev->bd_inode->i_mapping;
	struct page *page;
	int ret = 0;

	page = read_mapping_page(mapping, start, NULL);

	if (IS_ERR(page))
		return -1;
	if (PageError(page)) {
		ret = -1;
		goto out;
	}
	memcpy(buffer, page_address(page), PAGE_CACHE_SIZE);

out:
	page_cache_release(page);

	return ret;
}

int blkdev_sync_read(struct shfs_sb_info *sbi, sector_t start, size_t len, char *buffer)
{
	int i;
	int ret;

	for (i = 0; i < len; i++) {
		ret = read_one_page(sbi, start + i,
				    buffer + ((sector_t) i << PAGE_CACHE_SHIFT));
		if (ret)
			return ret;
	}

	return 0;
}

int blkdev_async_io(struct blkdev *bd, sector_t start, sector_t len,
                                  int write, void *buffer, blkdev_aiocb_t *cb, void *cb_argp)
{
	SHFS_AIO_TOKEN *t = cb_argp;
	BUG_ON(write);

	if (t->cb) {
		t->infly = 0;
		t->cb(t, t->cb_cookie, t->cb_argp);
	}
	return blkdev_sync_read(bd, start, len, buffer);
}
