/*
 * Simon's HashFS (SHFS) for Mini-OS
 *
 * Copyright(C) 2013-2014 NEC Laboratories Europe. All rights reserved.
 *                        Simon Kuenzer <simon.kuenzer@neclab.eu>
 */
#include <mini-os/os.h>
#include <mini-os/xmalloc.h>
#include <mini-os/types.h>
#include <stdint.h>
#include <errno.h>
#include <mempool.h>

#include "shfs.h"
#include "shfs_check.h"
#include "shfs_defs.h"

static int mounted = 0;

int mount_shfs(struct blkdev *bd[], unsigned int count) {
	void *chk0;
	void *chk1;
	sector_t len;
	int ret = 0;

	if (count == 0 || count > 1)
		return -EINVAL;	/* For now, just a single disk is supported */

	chk0 = _xmalloc(4096, 4096);
	if (!chk0) {
		ret = -ENOMEM;
		goto err;
	}

	/* read first chunk (considered as 4K) */
	len = 4096 / blkdev_ssize(bd[0]);
	ret = blkdev_sync_read(bd[0], 0, len, chk0);
	if (ret < 0)
		goto err_free_chk0;

	/* Try to detect the SHFS disk label */
	ret = shfs_detect_hdr0(chk0);
	if (ret < 0)
		goto err_free_chk0;

	

	return 0;

	// err_free_chk1:
	//xfree(chk1);
 err_free_chk0:
	xfree(chk0);
 err:
	return ret;
}

void unmount_shfs(void) {
}
