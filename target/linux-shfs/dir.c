#define SHFS_OPENBYNAME

#include <linux/printk.h>
#include <linux/fs.h>
#include "shfs.h"
#include "htable.h"
#include "shfs_btable.h"
#include "shfs_fio.h"

static int shfs_readdir(struct file *file, struct dir_context *ctx)
{
	struct htable_el *el;
	struct shfs_bentry *bentry;
	struct shfs_hentry *hentry;
	int cur_pos = 2;

	pr_info("shfs readdir\n");
	if (ctx->pos == 0 && !dir_emit_dots(file, ctx))
		goto out;

	foreach_htable_el(shfs_vol.bt, el) {
		int len;
		if (cur_pos++ != ctx->pos)
			continue;

		bentry = el->private;
		hentry = (struct shfs_hentry *)
			((uint8_t *) shfs_vol.htable_chunk_cache[bentry->hentry_htchunk]
			 + bentry->hentry_htoffset);

		pr_info("\t one shfs entry: ino=%d, name=%s\n",
			bentry->ino, hentry->name);
		len = strnlen(hentry->name, sizeof(hentry->name));
		if (!dir_emit(ctx, hentry->name, len, bentry->ino, DT_REG))
			goto out;
		ctx->pos++;
	}
out:
	return 0;
}

static struct dentry *shfs_lookup(struct inode * dir,
				  struct dentry *dentry,
				  unsigned int flags)
{
	struct super_block *sb = dir->i_sb;
	struct inode *inode;
	struct shfs_bentry *bentry;
	int ret = 0;

	bentry = _shfs_lookup_bentry_by_name(dentry->d_name.name);
	if (!bentry)
		return ERR_PTR(-ENOENT);

	inode = iget_locked(sb, (unsigned long) bentry->ino);
	if (!inode)
		return ERR_PTR(-ENOMEM);
	if (!(inode->i_state & I_NEW))
		goto out;

	inode->i_mode = 0;
	inode->i_mode |= S_IFREG + S_IRWXU + S_IRWXG + S_IRWXO;
	/* inode->i_fop = &shfs_dir_operations; */
	/* inode->i_op = &shfs_dir_inode_operations; */

	inode->i_size = 1;

	unlock_new_inode(inode);

out:
	return d_splice_alias(inode, dentry);

/* err_exit: */
/* 	iget_failed(inode); */
/* 	return ERR_PTR(ret); */
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
