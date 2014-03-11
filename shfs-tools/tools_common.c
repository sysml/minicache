#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <getopt.h>
#include <unistd.h>
#include <fcntl.h>

#include "tools_common.h"

struct disk *open_disk(const char *path, int mode)
{
	struct disk *d = NULL;
	struct stat fd_stat;
	int err;

	d = malloc(sizeof(*d));
	if (!d) {
		fatal();
		goto err_out;
	}

	d->path = strdup(path);
	if (!d->path) {
		fatal();
		goto err_free_d;
	}

	d->fd = open(d->path, mode);
	if (d->fd < 0) {
		eprintf("Could not open %s: %s\n", path , strerror(errno));
		goto err_free_path;
	}

	if (fstat(d->fd, &fd_stat) == -1) {
		eprintf("Could not retrieve stats from %s: %s\n", path, strerror(errno));
		goto err_free_path;
	}
	if (!S_ISBLK(fd_stat.st_mode) && !S_ISREG(fd_stat.st_mode)) {
		eprintf("%s is not a block device or a regular file\n", path);
		goto err_free_path;
	}
	if (!S_ISBLK(fd_stat.st_mode))
		dprintf(D_L0, "Note: %s is not a block device\n", path);

	/* get device size in bytes */
	if (S_ISBLK(fd_stat.st_mode)) {
		err = ioctl(d->fd, BLKGETSIZE64, &d->size);
		if (err) {
			unsigned long size32;

			dprintf(D_L0, "BLKGETSIZE64 failed. Trying BLKGETSIZE\n", path);
			err = ioctl(d->fd, BLKGETSIZE, &size32);
			if (err) {
				eprintf("Could not query device size from %s\n", path);
				goto err_free_path;
			}
			d->size = (uint64_t) size32;
		}
	} else {
		d->size = (uint64_t) fd_stat.st_size;
	}
	dprintf(D_L0, "%s has a size of %lld bytes\n", path, d->size);

	/* get prefered block size in bytes */
	d->blksize = fd_stat.st_blksize;
	dprintf(D_L0, "%s has a block size of %lld bytes\n", path, d->blksize);

	return d;

 err_free_path:
	free(d->path);
 err_free_d:
	free(d);
 err_out:
	return NULL;
}

void close_disk(struct disk *d) {
	dprintf(D_L0, "Syncing %s...\n", d->path);
	fsync(d->fd); /* ignore errors */
	close(d->fd);
	free(d->path);
	free(d);
}

void print_shfs_hdr_summary(struct shfs_hdr_common *hdr_common,
                            struct shfs_hdr_config *hdr_config)
{
	char     volname[17];
	uint64_t chunksize;
	uint64_t hentry_size;
	uint64_t htable_size;
	chk_t    htable_size_chks;
	uint32_t htable_total_entries;
	uint8_t  m;
	char str_uuid[17];

	chunksize            = SHFS_CHUNKSIZE(hdr_common);
	hentry_size          = SHFS_HENTRY_SIZE;
	htable_total_entries = SHFS_HTABLE_NB_ENTRIES(hdr_config);
	htable_size_chks     = SHFS_HTABLE_SIZE_CHUNKS(hdr_config, chunksize);
	htable_size          = CHUNKS_TO_BYTES(htable_size_chks, chunksize);

	printf("SHFS version:       0x%02x%02x\n",
	       hdr_common->version[1],
	       hdr_common->version[0]);
	strncpy(volname, hdr_common->vol_name, 16);
	volname[17] = '\0';
	printf("Volume name:        %s\n", volname);
	uuid_unparse(hdr_common->vol_uuid, str_uuid);
	printf("Volume UUID:        %s\n", str_uuid);
	printf("Chunksize:          %lu KiB\n",
	       chunksize / 1024);
	printf("Volume size:        %lu KiB\n",
	       (chunksize * hdr_common->vol_size) / 1024);

	printf("Hash function:      %s (%ld bits)\n",
	       (hdr_config->hfunc == SHFUNC_SHA ? "SHA" : "Unknown"),
	       hdr_config->hlen * 8);
	printf("Hash table:         %lu entries in %ld buckets\n" \
	       "                    %lu chunks (%ld KiB)\n" \
	       "                    %s\n",
	       htable_total_entries, hdr_config->htable_bucket_count,
	       htable_size_chks, htable_size / 1024,
	       hdr_config->htable_bak_ref ? "2nd copy enabled" : "No copy");
	printf("Entry size:         %lu Bytes (raw: %ld Bytes)\n", hentry_size, sizeof(struct shfs_hentry));
	printf("Metadata total:     %lu chunks\n", metadata_size(hdr_common, hdr_config));
	printf("Available space:    %lu chunks\n", avail_space(hdr_common, hdr_config));

	printf("\n");
	printf("Member stripe size: %u KiB\n", hdr_common->member_stripesize / 1024);
	printf("Volume members:     %u device(s)\n", hdr_common->member_count);
	for (m = 0; m < hdr_common->member_count; m++) {
		uuid_unparse(hdr_common->member[m].uuid, str_uuid);
		printf("  Member %2d UUID:   %s\n", m, str_uuid);
	}
}

chk_t metadata_size(struct shfs_hdr_common *hdr_common,
                    struct shfs_hdr_config *hdr_config)
{
	uint64_t chunksize;
	chk_t    htable_size_chks;
	chk_t    ret = 0;

	chunksize        = SHFS_CHUNKSIZE(hdr_common);
	htable_size_chks = SHFS_HTABLE_SIZE_CHUNKS(hdr_config, chunksize);

	ret += 1; /* chunk0 (common hdr) */
	ret += 1; /* chunk1 (config hdr) */
	ret += htable_size_chks; /* hash table chunks */
	if (hdr_config->htable_bak_ref)
		ret += htable_size_chks; /* backup hash table */
	return ret;
}

chk_t avail_space(struct shfs_hdr_common *hdr_common,
                  struct shfs_hdr_config *hdr_config)
{
	return hdr_common->vol_size - metadata_size(hdr_common, hdr_config);
}
