/*
 * Block device abstraction level for SHFS
 *
 * Authors: Yuri Volchkov <iurii.volchkov@neclab.eu>
 *
 *
 * Copyright (c) 2013-2017, NEC Europe Ltd., NEC Corporation All rights reserved.
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

#include "shfs.h"
#include <linux/pagemap.h>

static inline int read_one_page(struct shfs_sb_info *sbi, sector_t start, char *buffer)
{
	struct address_space *mapping = sbi->sb->s_bdev->bd_inode->i_mapping;
	struct page *page;
	int ret = 0;

	page = read_mapping_page(mapping, start, NULL);

	if (IS_ERR(page))
		return -1;
	if (PageError(page)) {
		ret = -1;
		goto out;
	}
	memcpy(buffer, page_address(page), PAGE_CACHE_SIZE);

out:
	page_cache_release(page);

	return ret;
}

int blkdev_sync_read(struct shfs_sb_info *sbi, sector_t start, size_t len, char *buffer)
{
	int i;
	int ret;

	for (i = 0; i < len; i++) {
		ret = read_one_page(sbi, start + i,
				    buffer + ((sector_t) i << PAGE_CACHE_SHIFT));
		if (ret)
			return ret;
	}

	return 0;
}

int blkdev_async_io(struct blkdev *bd, sector_t start, sector_t len,
                                  int write, void *buffer, blkdev_aiocb_t *cb, void *cb_argp)
{
	SHFS_AIO_TOKEN *t = cb_argp;
	BUG_ON(write);

	if (t->cb) {
		t->infly = 0;
		t->cb(t, t->cb_cookie, t->cb_argp);
	}
	return blkdev_sync_read(bd, start, len, buffer);
}
