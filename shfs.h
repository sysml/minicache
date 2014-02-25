/*
 * Simon's HashFS (SHFS) for Mini-OS
 *
 * Copyright(C) 2013-2014 NEC Laboratories Europe. All rights reserved.
 *                        Simon Kuenzer <simon.kuenzer@neclab.eu>
 */
#ifndef _SHFS_H_
#define _SHFS_H_

#include "blkdev.h"

int mount_shfs(struct blkdev *bd[], unsigned int count);
void unmount_shfs(void);

#endif /* _SHFS_H_ */
