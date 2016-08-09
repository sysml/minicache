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

#define SHFS_SIMLINK_INODE_N(file_inode_n) (file_inode_n + \
					    shfs_vol.htable_nb_entries + \
					    LINUX_FIRST_INO_N)

struct shfs_inode_info {
	struct inode	vfs_inode;
	struct shfs_bentry *bentry;
};

static inline struct shfs_inode_info *SHFS_I(struct inode *inode)
{
	return container_of(inode, struct shfs_inode_info, vfs_inode);
}

#endif
