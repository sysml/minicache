/*
 * SHFS inodes handling functions
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
