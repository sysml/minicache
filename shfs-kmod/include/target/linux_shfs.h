/*
 * SHFS linux definitions
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
 */

#ifndef _LINUX_SHFS_H
#define _LINUX_SHFS_H
#include <linux/fs.h>

struct shfs_sb_info {
	struct super_block *sb;
	size_t size;
	int chunk_size_shift;
};

struct inode *shfs_get_root_inode(struct shfs_sb_info *sbi);

extern const struct file_operations shfs_dir_operations;
extern const struct inode_operations shfs_dir_inode_operations;
extern  const struct address_space_operations shfs_aops;


#define SHFS_SIMLINK_INODE_N(file_inode_n) (file_inode_n + \
					    shfs_vol.htable_nb_entries + \
					    LINUX_FIRST_INO_N)

struct shfs_inode_info {
	struct inode	vfs_inode;
	struct shfs_bentry *bentry;
	sector_t start_block;
};

static inline struct shfs_inode_info *SHFS_I(struct inode *inode)
{
	return container_of(inode, struct shfs_inode_info, vfs_inode);
}

static inline struct shfs_sb_info *SHFS_SB(struct super_block *sb)
{
	return sb->s_fs_info;
}

#define CHUNK_SIZE_MASK(sbi) ((1 << sbi->chunk_size_shift) - 1)

#endif
