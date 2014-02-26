/*
 * Simon's HashFS (SHFS) for Mini-OS
 *
 * Copyright(C) 2013-2014 NEC Laboratories Europe. All rights reserved.
 *                        Simon Kuenzer <simon.kuenzer@neclab.eu>
 */
#ifndef _SHFS_H_
#define _SHFS_H_

#include <mini-os/types.h>
#include <stdint.h>
#include <semaphore.h>
#include "blkdev.h"

#include "shfs_defs.h"

struct vol_member {
	struct blkdev *bd;
	uuid_t uuid;
	sector_t sfactor;
};

struct vol_info {
	uuid_t uuid;
	char volname[17];
	uint32_t chunksize;
	chk_t volsize;

	uint8_t nb_members;
	struct vol_member member[SHFS_MAX_NB_MEMBERS];
	uint32_t stripesize;
};

extern struct vol_info shfs_vol;
extern struct semaphore shfs_mount_lock;
extern volatile int shfs_mounted;

int init_shfs(void);
int mount_shfs(struct blkdev *bd[], unsigned int count);
void umount_shfs(void);
void exit_shfs(void);

#endif /* _SHFS_H_ */
