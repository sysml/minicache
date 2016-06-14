#ifndef _LINUX_SHFS_H
#define _LINUX_SHFS_H
#include <linux/fs.h>

struct shfs_sb_info {
	struct super_block *sb;
	size_t size;
};

struct inode *shfs_get_root_inode(struct shfs_sb_info *sbi);

#endif
