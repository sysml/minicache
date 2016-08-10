#include <linux/printk.h>
#include <linux/fs.h>
#include <linux/mpage.h>
#include <linux/buffer_head.h>
#include "shfs.h"
#include "htable.h"
#include "shfs_btable.h"
#include "shfs_fio.h"

int shfs_get_block(struct inode *inode,
		   sector_t iblock,
		   struct buffer_head *bh_result,
		   int create)
{
	/* struct hentry *hentry = SHFS_I(inode)->bentry->hentry; */
	/* struct shfs_sb_info *sbi = SHFS_SB(inode->i_sb); */

	sector_t block = iblock + SHFS_I(inode)->start_block;
	map_bh(bh_result, inode->i_sb, block);
	bh_result->b_size = 4096;
	return 0;
}

static int shfs_readpage(struct file *file, struct page *page)
{
	return mpage_readpage(page, shfs_get_block);
}

static int
shfs_readpages(struct file *file, struct address_space *mapping,
		struct list_head *pages, unsigned nr_pages)
{
	return mpage_readpages(mapping, pages, nr_pages, shfs_get_block);
}

static sector_t shfs_bmap(struct address_space *mapping, sector_t block)
{
	return generic_block_bmap(mapping, block, shfs_get_block);
}

const struct address_space_operations shfs_aops = {
	.readpage		= shfs_readpage,
	.readpages		= shfs_readpages,
	.bmap			= shfs_bmap,
	/* .direct_IO		= shfs_direct_IO, */
};
