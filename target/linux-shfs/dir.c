#define SHFS_OPENBYNAME

#include <linux/printk.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include "shfs.h"
#include "htable.h"
#include "shfs_btable.h"
#include "shfs_fio.h"

enum  special_inode_nums {
	SHFS_ROOT_INO = 1,
	SHFS_NAMES_DIR_INO,
	SHFS_HASHES_DIR_INO,
};

static inline bool dir_emit_rootdirs(struct dir_context *ctx)
{
#define SHFS_NAMES_DIR "names"
#define SHFS_HASHES_DIR "hashes"
	if (ctx->pos == 2) {
		if (!dir_emit(ctx, SHFS_NAMES_DIR, sizeof(SHFS_NAMES_DIR),
			      SHFS_NAMES_DIR_INO, DT_DIR))
			return false;
		ctx->pos = 3;
	}

	if (ctx->pos == 3) {
		if (!dir_emit(ctx, SHFS_HASHES_DIR, sizeof(SHFS_HASHES_DIR),
			      SHFS_HASHES_DIR_INO, DT_DIR))
			return false;
		ctx->pos = 4;
	}

	return true;
}

static inline char *hash2str(hash512_t hash, char *buf, int hash_len)
{
#define onechar(a) ((a) > 0x9 ? (a) + 'a' - 0xa : (a) + '0')
#define lowchar(b) (onechar((uint8_t) b & 0x0f))
#define highchar(c) (onechar((uint8_t) c >> 4))
	int i;
	for (i = 0; i < hash_len; i++) {
		buf[i<<1] = highchar(hash[i]);
		buf[(i<<1) + 1] = lowchar(hash[i]);
	}
	buf[hash_len << 1] = '\0';

	return buf;
}

#define SHFS_MAX_HASH_STR_LEN (sizeof(hash512_t) * 2 + 1)
static inline int dir_emit_names(struct dir_context *ctx, int emit_hashes)
{
	struct htable_el *el;
	struct shfs_bentry *bentry;
	struct shfs_hentry *hentry;
	int cur_pos = 2;
	BUILD_BUG_ON(sizeof(hash512_t) > 64);

	foreach_htable_el(shfs_vol.bt, el) {
		char *name;
		int len;
		unsigned type;
		u64 ino;
		char hash_name[SHFS_MAX_HASH_STR_LEN];

		if (cur_pos++ != ctx->pos)
			continue;

		bentry = el->private;
		hentry = bentry->hentry;

		if (emit_hashes) {
			name = hash2str(hentry->hash, hash_name, shfs_vol.hlen);
			len = shfs_vol.hlen*2;
			type = DT_REG;
			ino = bentry->ino;
		} else {
			name = hentry->name;
			len = strnlen(name, sizeof(hentry->name));
			type = DT_LNK;
			ino = SHFS_SIMLINK_INODE_N(bentry->ino);
		}

		if (!dir_emit(ctx, name, len, ino, type))
			return 0;
		ctx->pos++;
	}

	return 0;
}


static int shfs_readdir(struct file *file, struct dir_context *ctx)
{
	if (ctx->pos == 0 && !dir_emit_dots(file, ctx))
		goto out;

	if (file->f_path.mnt->mnt_root == file->f_path.dentry) {
		if (!dir_emit_rootdirs(ctx)) {
			pr_err("failed to emit special dirs\n");
			goto out;
		}
	} else if (file->f_path.dentry->d_inode->i_ino ==
		   SHFS_NAMES_DIR_INO) {
		return dir_emit_names(ctx, 0);
	} else if (file->f_path.dentry->d_inode->i_ino ==
		   SHFS_HASHES_DIR_INO) {
		return dir_emit_names(ctx, 1);
	}

out:
	return 0;
}

#define SHFS_LINK_PREFIX ("../" SHFS_HASHES_DIR "/")
#define SHFS_LINK_PATH_LEN (SHFS_MAX_HASH_STR_LEN + sizeof(SHFS_LINK_PREFIX))
static void *shfs_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	char *path = kmalloc(SHFS_LINK_PATH_LEN, GFP_NOFS);
	if (!path)
		return ERR_CAST(path);
	memcpy(path, SHFS_LINK_PREFIX, sizeof(SHFS_LINK_PREFIX) - 1);
	hash2str(SHFS_I(dentry->d_inode)->bentry->hentry->hash,
		       path + sizeof(SHFS_LINK_PREFIX) - 1,
		       shfs_vol.hlen);

	nd_set_link(nd, path);
	return path;
}

static void shfs_put_link(struct dentry *dentry, struct nameidata *nd, void *cookie)
{
	kfree(cookie);
}

static const struct inode_operations shfs_symlink_inode_operations = {
	.readlink	= generic_readlink,
	.follow_link	= shfs_follow_link,
	.put_link	= shfs_put_link,
};

static struct dentry *shfs_lookup(struct inode * dir,
				  struct dentry *dentry,
				  unsigned int flags)
{
	struct super_block *sb = dir->i_sb;
	struct inode *inode;
	struct shfs_bentry *bentry = NULL;
	hash512_t hash;
	int new_inode_n = 0;
	umode_t new_inode_mode;

	switch (dir->i_ino) {
	case SHFS_ROOT_INO:
		if (!strcmp(dentry->d_name.name, SHFS_NAMES_DIR))
			new_inode_n = SHFS_NAMES_DIR_INO;
		else if (!strcmp(dentry->d_name.name, SHFS_HASHES_DIR))
			new_inode_n = SHFS_HASHES_DIR_INO;
		else
			return ERR_PTR(-ENOENT);

		new_inode_mode = S_IFDIR + S_IRWXU + S_IRWXG + S_IRWXO;
		break;
	case SHFS_NAMES_DIR_INO:
		bentry = _shfs_lookup_bentry_by_name(dentry->d_name.name);
		if (!bentry)
			return ERR_PTR(-ENOENT);
		new_inode_mode = S_IFLNK + S_IRUSR + S_IRGRP + S_IROTH;
		new_inode_n = SHFS_SIMLINK_INODE_N(bentry->ino);
		break;
	case SHFS_HASHES_DIR_INO:
		if (hash_parse(dentry->d_name.name, hash, shfs_vol.hlen)) {
			pr_err("unable to parse hash\n");
			return ERR_PTR(-ENOENT);
		}
		bentry = _shfs_lookup_bentry_by_hash(hash);
		if (!bentry)
			return ERR_PTR(-ENOENT);
		new_inode_mode = S_IFREG + S_IRUSR + S_IRGRP + S_IROTH;
		new_inode_n = bentry->ino;
		break;
	default:
		BUG();
	}

	inode = iget_locked(sb, new_inode_n);
	if (!inode)
		return ERR_PTR(-ENOMEM);
	if (!(inode->i_state & I_NEW))
		goto out;

	inode->i_mode = new_inode_mode;
	inode->i_size = 1;
	SHFS_I(inode)->bentry = bentry;

	if (S_ISDIR(inode->i_mode)) {
		inode->i_fop = &shfs_dir_operations;
		inode->i_op = &shfs_dir_inode_operations;
	} else if (S_ISLNK(inode->i_mode)) {
		inode->i_op = &shfs_symlink_inode_operations;
	}

	unlock_new_inode(inode);

out:
	return d_splice_alias(inode, dentry);

/* err_exit: */
/* 	iget_failed(inode); */
/* 	return ERR_PTR(ret); */
}

const struct file_operations shfs_dir_operations = {
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

	inode = iget_locked(sbi->sb, SHFS_ROOT_INO);
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
