/*
 * Simon's HashFS (SHFS) for Mini-OS
 *
 * Copyright(C) 2013-2014 NEC Laboratories Europe. All rights reserved.
 *                        Simon Kuenzer <simon.kuenzer@neclab.eu>
 */
#include <stdio.h>

#include "shfs_tools.h"

#include "shfs.h"
#include "shfs_htable.h"
#include "shell.h"

static int shcmd_shfs_ls(FILE *cio, int argc, char *argv[])
{
	struct shfs_bentry *bentry;
	struct shfs_hentry *hentry;
	char str_hash[(shfs_vol.hlen * 2) + 1];
	char str_mime[sizeof(hentry->mime) + 1];
	char str_name[sizeof(hentry->name) + 1];
	unsigned int i;

	down(&shfs_mount_lock);
	if (!shfs_mounted) {
		fprintf(cio, "No SHFS filesystem mounted\n");
		goto out;
	}

	str_hash[(shfs_vol.hlen * 2)] = '\0';
	str_name[sizeof(hentry->name)] = '\0';

	if (shfs_vol.hlen <= 32)
		fprintf(cio, "%-64s %12s %12s %-16s %s\n",
		       "Hash",
		       "At (chk)",
		       "Size (chk)",
		       "MIME",
		       "Name");
	else
		fprintf(cio, "%-128s %12s %12s %-16s %s\n",
		       "Hash",
		       "At (chk)",
		       "Size (chk)",
		       "MIME",
		       "Name");
	for (i = 0; i < shfs_vol.htable_nb_entries; ++i) {
		bentry = shfs_btable_pick(shfs_vol.bt, i);
		hentry = (struct shfs_hentry *)
			((uint8_t *) shfs_vol.htable_chunk_cache[bentry->hentry_htchunk]
			 + bentry->hentry_htoffset);
		if (!hash_is_zero(bentry->hash, shfs_vol.hlen)) {
			hash_unparse(bentry->hash, shfs_vol.hlen, str_hash);
			strncpy(str_name, hentry->name, sizeof(hentry->name));
			strncpy(str_mime, hentry->mime, sizeof(hentry->mime));
			if (shfs_vol.hlen <= 32)
				fprintf(cio, "%-64s %12lu %12lu %-16s %s\n",
				       str_hash,
				       hentry->chunk,
				       BYTES_TO_CHUNKS(hentry->len + hentry->offset, shfs_vol.chunksize),
				       str_mime,
				       str_name);
			else
				fprintf(cio, "%-128s %12lu %12lu %-16s %s\n",
				       str_hash,
				       hentry->chunk,
				       BYTES_TO_CHUNKS(hentry->len + hentry->offset, shfs_vol.chunksize),
				       str_mime,
				       str_name);
		}
	}

 out:
	up(&shfs_mount_lock);
	return 0;
}

static int shcmd_shfs_info(FILE *cio, int argc, char *argv[])
{
	unsigned int m;
	char str_uuid[17];

	down(&shfs_mount_lock);
	if (!shfs_mounted) {
		fprintf(cio, "No SHFS filesystem mounted\n");
		goto out;
	}

	fprintf(cio, "SHFS version:       0x%02x%02x\n",
	        SHFSv1_VERSION1,
	        SHFSv1_VERSION0);
	fprintf(cio, "Volume name:        %s\n", shfs_vol.volname);
	uuid_unparse(shfs_vol.uuid, str_uuid);
	fprintf(cio, "Volume UUID:        %s\n", str_uuid);
	fprintf(cio, "Chunksize:          %lu KiB\n",
	        shfs_vol.chunksize / 1024);
	fprintf(cio, "Volume size:        %lu KiB\n",
	        CHUNKS_TO_BYTES(shfs_vol.volsize, shfs_vol.chunksize) / 1024);
	fprintf(cio, "Hash table:         %lu entries in %ld buckets\n" \
	        "                    %lu chunks (%ld KiB)\n" \
	        "                    %s\n",
	        shfs_vol.htable_nb_entries, shfs_vol.htable_nb_buckets,
	        shfs_vol.htable_len, CHUNKS_TO_BYTES(shfs_vol.htable_len, shfs_vol.chunksize) / 1024,
	        shfs_vol.htable_bak_ref ? "2nd copy enabled" : "No copy");
	fprintf(cio, "Entry size:         %lu Bytes (raw: %ld Bytes)\n",
	        SHFS_HENTRY_SIZE, sizeof(struct shfs_hentry));

	fprintf(cio, "\n");
	fprintf(cio, "Member stripe size: %u KiB\n", shfs_vol.stripesize / 1024);
	fprintf(cio, "Volume members:     %u device(s)\n", shfs_vol.nb_members);
	for (m = 0; m < shfs_vol.nb_members; m++) {
		uuid_unparse(shfs_vol.member[m].uuid, str_uuid);
		fprintf(cio, "  Member %2d:\n", m);
		fprintf(cio, "    VBD:            %u\n", shfs_vol.member[m].bd->vbd_id);
		fprintf(cio, "    UUID:           %s\n", str_uuid);
		fprintf(cio, "    Block size:     %u\n", blkdev_ssize(shfs_vol.member[m].bd));
	}



 out:
	up(&shfs_mount_lock);
	return 0;
}

int register_shfs_tools(void)
{
	int ret;
	ret = shell_register_cmd("ls", shcmd_shfs_ls);
	ret = shell_register_cmd("shfs-info", shcmd_shfs_info);
	if (ret < 0)
		return ret;

	return 0;
}

void uuid_unparse(const uuid_t uu, char *out)
{
	sprintf(out, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
	        uu[0], uu[1], uu[2], uu[3], uu[4], uu[5], uu[6], uu[7],
	        uu[8], uu[9], uu[10], uu[11], uu[12], uu[13], uu[14], uu[15]);
}

int uuid_compare(const uuid_t uu1, const uuid_t uu2)
{
	return memcmp(uu1, uu2, sizeof(uuid_t));
}

int uuid_is_zero(const uuid_t uu)
{
	unsigned i;
	for (i = 0; i < sizeof(uuid_t); ++i)
		if (uu[i] != 0)
			return 0;
	return 1;
}

int uuid_is_null(const uuid_t uu)
{
	return (uu == NULL);
}

void uuid_copy(uuid_t dst, const uuid_t src)
{
	memcpy(dst, src, sizeof(uuid_t));
}
