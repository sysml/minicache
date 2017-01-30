/*
 * SHFS module initialization and mounting
 *
 * Authors: Yuri Volchkov <iurii.volchkov@neclab.eu>
 *
 *
 * Copyright (c) 2013-2017, NEC Europe Ltd., NEC Corporation All rights reserved
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, or the BSD license below:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * THIS HEADER MAY NOT BE EXTRACTED OR MODIFIED IN ANY WAY.
 */

#include <linux/module.h>

#include <linux/init.h>
#include <linux/printk.h>
#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/log2.h>
#include "shfs.h"

static struct kmem_cache *shfs_inode_cachep;

static struct inode *shfs_alloc_inode(struct super_block *sb)
{
	struct shfs_inode_info *inode;

	inode = kmem_cache_alloc(shfs_inode_cachep, GFP_NOFS);
	if (!inode)
		return NULL;

	return &inode->vfs_inode;
}

static void shfs_i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);
	struct shfs_inode_info *inode_info = SHFS_I(inode);

	kmem_cache_free(shfs_inode_cachep, inode_info);
}

static void shfs_destroy_inode(struct inode *inode)
{
	call_rcu(&inode->i_rcu, shfs_i_callback);
}

static void shfs_put_super (struct super_block * sb)
{
	umount_shfs(1);
	kfree(SHFS_SB(sb));
	memset(&shfs_vol, 0, sizeof(shfs_vol));
}

static struct super_operations shfs_sops = {
	.alloc_inode = shfs_alloc_inode,
	.destroy_inode = shfs_destroy_inode,
	.put_super = shfs_put_super,
};

static inline int mount_shfs_glue(struct shfs_sb_info *sbi)
{
	return mount_shfs((blkdev_id_t *) &sbi, 1);
}

static int shfs_fill_super(struct super_block *sb, void *data, int silent)
{
	struct inode *root_inode;
	struct shfs_sb_info *sbi;
	int ret = 0;

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
	if (IS_ERR(root_inode))
		goto err_out;
	sb->s_root = d_make_root(root_inode);
	if (IS_ERR(sb->s_root))
		goto err_out;

	sb->s_flags |= MS_RDONLY;

	ret = mount_shfs_glue(sbi);
	if (ret)
		goto err_out;


	sbi->chunk_size_shift = ilog2(shfs_vol.chunksize);
	if (!is_power_of_2(shfs_vol.chunksize)) {
		pr_err("Can't mount: chunk size is not power of 2\n");
		goto err_out;
	} else if (shfs_vol.chunksize < PAGE_CACHE_SIZE) {
		pr_err("Can't mount: chunk size is smaller then %lu\n",
		       PAGE_CACHE_SIZE);
		goto err_out;
	}

	/* shfs_test(sbi); */
	return 0;

err_out:
	/* TODO: proper error path cleanup */
	kfree(sbi);
	return ret;
}

static struct dentry *shfs_linux_mount(struct file_system_type *fs_type, int flags,
		       const char *dev_name, void *data)
{
	return mount_bdev(fs_type, flags, dev_name, data, shfs_fill_super);
}

static struct file_system_type shfs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "shfs",
	.mount		= shfs_linux_mount,
	.kill_sb	= kill_block_super,
	.fs_flags	= FS_REQUIRES_DEV,
};

static void shfs_init_inode_once(void *generic_inode)
{
	struct shfs_inode_info *inode = SHFS_I(generic_inode);
	inode_init_once(&inode->vfs_inode);
}

static int __init shfs_init(void)
{
	int err = 0;

	shfs_inode_cachep = kmem_cache_create("shfs_icache",
					       sizeof(struct shfs_inode_info), 0,
					       SLAB_HWCACHE_ALIGN, shfs_init_inode_once);
	if (!shfs_inode_cachep) {
		pr_err("failed to initialise inode cache\n");
		return -ENOMEM;
	}

	err = register_filesystem(&shfs_fs_type);
	if (err)
		goto out;

out:
	return err;
}

static void __exit shfs_exit(void)
{
	unregister_filesystem(&shfs_fs_type);

	rcu_barrier();
	kmem_cache_destroy(shfs_inode_cachep);
}

MODULE_AUTHOR("Simon Kuenzer, Yuri Volchkov");
MODULE_DESCRIPTION("Simple Hash File System");
MODULE_LICENSE("Dual BSD/GPL");
module_init(shfs_init);
module_exit(shfs_exit)
