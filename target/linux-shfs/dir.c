#include <linux/printk.h>
#include <linux/fs.h>
#include "shfs.h"

static int shfs_readdir(struct file *file, struct dir_context *ctx)
{
	pr_info("shfs readdir\n");
	if (!dir_emit_dots(file, ctx))
		goto out;
out:
	return 0;
}

static struct dentry *shfs_lookup(struct inode * dir,
				  struct dentry *dentry,
				  unsigned int flags)
{
	BUG();
}

static const struct file_operations shfs_dir_operations = {
	/* .llseek		=  */
	.read		= generic_read_dir,
	.iterate	= shfs_readdir,
	/* .release	=  */
	/* .unlocked_ioctl =  */
	/* .fsync		=  */
};

const struct inode_operations shfs_dir_inode_operations = {
	.lookup		= shfs_lookup,
};


struct inode *shfs_get_root_inode(struct shfs_sb_info *sbi)
{
	struct inode *inode;

	inode = iget_locked(sbi->sb, 1);
	if (!inode) {
		inode = ERR_PTR(-ENOMEM);
		goto exit;
	}
	if (!(inode->i_state & I_NEW))
		return inode;

	inode->i_mode = 0;
	inode->i_mode |= S_IFDIR + S_IRWXU + S_IRWXG + S_IRWXO;
	inode->i_fop = &shfs_dir_operations;
	inode->i_op = &shfs_dir_inode_operations;
	inode->i_size = 1;
	unlock_new_inode(inode);
exit:
	return inode;
}
