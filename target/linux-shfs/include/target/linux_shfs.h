#ifndef _LINUX_SHFS_H
#define _LINUX_SHFS_H
#include <linux/fs.h>

struct shfs_sb_info {
	struct super_block *sb;
	size_t size;
};

struct inode *shfs_get_root_inode(struct shfs_sb_info *sbi);

extern const struct file_operations shfs_dir_operations;
extern const struct inode_operations shfs_dir_inode_operations;
#endif
