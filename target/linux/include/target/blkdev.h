#ifndef _BLKDEV_H_
#define _BLKDEV_H_

#if defined CONFIG_OSVBLK
#include <blkdev/osv-blk.h>
#else
#include <blkdev/paio-blk.h>
#endif

#endif
