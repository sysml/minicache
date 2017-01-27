obj-$(CONFIG_SHFS_FS) += shfs_all.o

ccflags-y := -Iminicache/target/linux-shfs/include
ccflags-y += -DSHFS_HASH_PARSE_CASE_SENSITIVE
shfs_all-y := shfs.o super.o dir.o blkdev.o shfs_check.o htable.o inode.o
