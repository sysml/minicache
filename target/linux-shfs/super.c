#include <linux/init.h>
#include <linux/printk.h>
#include <linux/fs.h>
#include "shfs.h"


static struct super_operations shfs_sops = {
	
};

static int shfs_fill_super(struct super_block *sb, void *data, int silent)
{
	struct inode *root_inode;
	struct shfs_sb_info *sbi;

	if (!sb)
		return -ENXIO;
	if (!sb->s_bdev)
		return -ENXIO;
	if (!sb->s_bdev->bd_part)
		return -ENXIO;

	sbi = kzalloc(sizeof(*sbi), GFP_NOFS);
	if (!sbi)
		return -ENOMEM;
	sb->s_fs_info = sbi;
	sbi->sb = sb;

	sb->s_op = &shfs_sops;

	root_inode = shfs_get_root_inode(sbi);
	sb->s_root = d_make_root(root_inode);

	sb->s_flags |= MS_RDONLY;
	return 0;
}

static struct dentry *shfs_linux_mount(struct file_system_type *fs_type, int flags,
		       const char *dev_name, void *data)
{
	return mount_bdev(fs_type, flags, dev_name, data, shfs_fill_super);
}

static struct file_system_type shfs_fs_type = {
	/* .owner		= THIS_MODULE, */
	.name		= "shfs",
	.mount		= shfs_linux_mount,
	.kill_sb	= kill_block_super,
	.fs_flags	= FS_REQUIRES_DEV,
};


static int __init shfs_init(void)
{
	int err = 0;

	err = register_filesystem(&shfs_fs_type);
	if (err)
		goto out;

out:
	return err;
}
late_initcall(shfs_init);
