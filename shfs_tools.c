/*
 * Simon's HashFS (SHFS) for Mini-OS
 *
 * Copyright(C) 2013-2014 NEC Laboratories Europe. All rights reserved.
 *                        Simon Kuenzer <simon.kuenzer@neclab.eu>
 */
#include <stdio.h>
#include <hexdump.h>

#include "shfs.h"
#include "shfs_btable.h"
#include "shfs_tools.h"
#include "shfs_fio.h"
#ifdef SHFS_STATS
#include "shfs_stats.h"
#endif
#include "shell.h"

static int shcmd_shfs_ls(FILE *cio, int argc, char *argv[])
{
	struct htable_el *el;
	struct shfs_bentry *bentry;
	struct shfs_hentry *hentry;
	char str_hash[(shfs_vol.hlen * 2) + 1];
	char str_mime[sizeof(hentry->mime) + 1];
	char str_name[sizeof(hentry->name) + 1];
	char str_date[20];

	down(&shfs_mount_lock);
	if (!shfs_mounted) {
		fprintf(cio, "No SHFS filesystem mounted\n");
		goto out;
	}

	str_hash[(shfs_vol.hlen * 2)] = '\0';
	str_name[sizeof(hentry->name)] = '\0';

	foreach_htable_el(shfs_vol.bt, el) {
		bentry = el->private;
		hentry = (struct shfs_hentry *)
			((uint8_t *) shfs_vol.htable_chunk_cache[bentry->hentry_htchunk]
			 + bentry->hentry_htoffset);
		hash_unparse(*el->h, shfs_vol.hlen, str_hash);
		strncpy(str_name, hentry->name, sizeof(hentry->name));
		strncpy(str_mime, hentry->mime, sizeof(hentry->mime));
		strftimestamp_s(str_date, sizeof(str_date),
		                "%b %e, %g %H:%M", hentry->ts_creation);
		fprintf(cio, "%c%s %12lu %12lu %-24s %-16s %s\n",
		        SFHS_HASH_INDICATOR_PREFIX,
		        str_hash,
		        hentry->chunk,
		        DIV_ROUND_UP(hentry->len + hentry->offset, shfs_vol.chunksize),
		        str_mime,
		        str_date,
		        str_name);
	}

 out:
	up(&shfs_mount_lock);
	return 0;
}

#ifdef SHFS_STATS
static int _shcmd_shfs_print_el_stats(void *argp, hash512_t h, int available, struct shfs_el_stats *stats)
{
	FILE *cio = (FILE *) argp;
	char str_hash[(shfs_vol.hlen * 2) + 1];
	char str_date[20];
#if defined SHFS_STATS_HTTP && defined SHFS_STATS_HTTP_DPC
	register unsigned int i;
#endif

	if (stats->laccess) {
		hash_unparse(h, shfs_vol.hlen, str_hash);
		strftimestamp_s(str_date, sizeof(str_date),
		                "%b %e, %g %H:%M", stats->laccess);
#ifdef SHFS_STATS_HTTP
		fprintf(cio, "%c%s %c%c %6u [ %6u | ",
		        SFHS_HASH_INDICATOR_PREFIX,
		        str_hash,
		        available ? 'I' : ' ',
		        available ? 'N' : ' ',
		        stats->h, /* hits */
		        stats->c ); /* completed file request */
#ifdef SHFS_STATS_HTTP_DPC
		for (i=0; i<SHFS_STATS_HTTP_DPCR; ++i)
			fprintf(cio, "%6u ", stats->p[i] );
#endif
		fprintf(cio, "] %6u %-16s\n",
			stats->m, /* missed */
		        str_date);
#else
		fprintf(cio, "%c%s %c%c %8u %8u %-16s\n",
		        SFHS_HASH_INDICATOR_PREFIX,
		        str_hash,
		        available ? 'I' : ' ',
		        available ? 'N' : ' ',
		        stats->h, /* hits */
		        stats->m, /* missed */
		        str_date);
#endif
	}

	return 0;
}

static int shcmd_shfs_stats(FILE *cio, int argc, char *argv[])
{
	down(&shfs_mount_lock);
	if (!shfs_mounted) {
		fprintf(cio, "No SHFS filesystem mounted\n");
		goto out;
	}

	shfs_dump_stats(_shcmd_shfs_print_el_stats, cio);
	if (shfs_vol.mstats.i)
		fprintf(cio, "Invalid element requests: %8lu\n", shfs_vol.mstats.i);
	if (shfs_vol.mstats.e)
		fprintf(cio, "Errors on requests:       %8lu\n", shfs_vol.mstats.e);

 out:
	up(&shfs_mount_lock);
	return 0;
}
#endif

static int shcmd_shfs_file(FILE *cio, int argc, char *argv[])
{
	char str_mime[128];
	uint64_t fsize;
	unsigned int i;
	SHFS_FD f;
	int ret = 0;

	if (argc <= 1) {
		fprintf(cio, "Usage: %s [FILE]...\n", argv[0]);
		return -1;
	}

	for (i = 1; i < argc; ++i) {
		f = shfs_fio_open(argv[i]);
		if (!f) {
			fprintf(cio, "%s: Could not open: %s\n", argv[1], strerror(errno));
			return -1;
		}
		shfs_fio_mime(f, str_mime, sizeof(str_mime));
		shfs_fio_size(f, &fsize);

		fprintf(cio, "%s: %s, ", argv[1], str_mime);
		if (fsize < 1024)
			fprintf(cio, "%lu B\n", fsize);
		else
			fprintf(cio, "%lu KiB\n", fsize / 1024);

		shfs_fio_close(f);
	}
	return ret;
}


static int shcmd_shfs_cat(FILE *cio, int argc, char *argv[])
{
	SHFS_FD f;
	char buf[129];
	uint64_t fsize, left, cur, dlen, plen;
	int ret = 0;

	if (argc <= 1) {
		fprintf(cio, "Usage: %s [FILE]\n", argv[0]);
		return -1;
	}

	f = shfs_fio_open(argv[1]);
	if (!f) {
		fprintf(cio, "%s: Could not open: %s\n", argv[1], strerror(errno));
		return -1;
	}
	shfs_fio_size(f, &fsize);

	left = fsize;
	cur = 0;
	while (left) {
		dlen = min(left, sizeof(buf) - 1);

		ret = shfs_fio_read(f, cur, buf, dlen);
		if (ret < 0) {
			fprintf(cio, "%s: Read error: %s\n", argv[1], strerror(-ret));
			goto out;
		}
		buf[dlen] = '\0'; /* set terminating character for fprintf */
		plen = fprintf(cio, "%s", buf);
		fflush(cio);
		if (plen < dlen) {
			/* terminating character found earlier than expected
			 * -> end of string in file */
			goto out;
		}
		left -= dlen;
		cur += dlen;
	}

 out:
	fflush(stdout);
	fflush(cio);
	shfs_fio_close(f);
	return ret;
}


static int shcmd_shfs_dumpfile(FILE *cio, int argc, char *argv[])
{
	SHFS_FD f;
	char buf[1024];
	uint64_t fsize, left, cur, dlen;
	int ret = 0;

	if (argc <= 1) {
		fprintf(cio, "Usage: %s [FILE]\n", argv[0]);
		return -1;
	}

	f = shfs_fio_open(argv[1]);
	if (!f) {
		fprintf(cio, "%s: Could not open: %s\n", argv[1], strerror(errno));
		return -1;
	}
	shfs_fio_size(f, &fsize);

	left = fsize;
	cur = 0;
	while (left) {
		dlen = min(left, sizeof(buf));
		ret = shfs_fio_read(f, cur, buf, dlen);
		if (ret < 0) {
			fprintf(cio, "%s: Read error: %s\n", argv[1], strerror(-ret));
			goto out;
		}
		hexdump(cio, buf, dlen, "", HDAT_RELATIVE, cur, 16, 4, 1);
		left -= dlen;
		cur += dlen;
	}

 out:
	shfs_fio_close(f);
	return ret;
}

static int shcmd_shfs_mount(FILE *cio, int argc, char *argv[])
{
    unsigned int vbd_id[MAX_NB_TRY_BLKDEVS];
    unsigned int count;
    unsigned int i, j;
    int ret;

    if ((argc + 1) > MAX_NB_TRY_BLKDEVS) {
	    fprintf(cio, "At most %u devices are supported\n", MAX_NB_TRY_BLKDEVS);
	    return -1;
    }
    if ((argc) == 1) {
	    fprintf(cio, "Usage: %s [vbd_id]...\n", argv[0]);
	    return -1;
    }
    for (i = 1; i < argc; ++i) {
	    if (sscanf(argv[i], "%u", &vbd_id[i - 1]) != 1) {
		    fprintf(cio, "Invalid argument %u\n", i);
		    return -1;
	    }
    }
    count = argc - 1;

    /* search for duplicates in the list
     * This is unfortunately an ugly & slow way of how it is done here... */
    for (i = 0; i < count; ++i)
	    for (j = 0; j < count; ++j)
		    if (i != j && vbd_id[i] == vbd_id[j]) {
			    fprintf(cio, "Found duplicates in the list\n");
			    return -1;
		    }

    ret = mount_shfs(vbd_id, count);
    if (ret == -EALREADY) {
	    fprintf(cio, "A filesystem is already mounted\nPlease unmount it first\n");
	    return -1;
    }
    if (ret < 0)
	    fprintf(cio, "Could not mount: %s\n", strerror(-ret));
    return ret;
}

static int shcmd_shfs_umount(FILE *cio, int argc, char *argv[])
{
    int ret;

    ret = umount_shfs();
    if (ret < 0)
	    fprintf(cio, "Could not unmount: %s\n", strerror(-ret));
    return ret;
}

static int shcmd_shfs_info(FILE *cio, int argc, char *argv[])
{
	unsigned int m;
	char str_uuid[17];
	char str_date[20];

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
	strftimestamp_s(str_date, sizeof(str_date),
	                "%b %e, %g %H:%M", shfs_vol.ts_creation);
	fprintf(cio, "Creation date:      %s\n", str_date);
	fprintf(cio, "Chunksize:          %lu KiB\n",
	        shfs_vol.chunksize / 1024);
	fprintf(cio, "Volume size:        %lu KiB\n",
	        CHUNKS_TO_BYTES(shfs_vol.volsize, shfs_vol.chunksize) / 1024);
	fprintf(cio, "Hash table:         %lu entries in %ld buckets\n" \
	        "                    %lu chunks (%ld KiB)\n" \
	        "                    %s\n",
	        shfs_vol.htable_nb_entries, shfs_vol.htable_nb_buckets,
	        shfs_vol.htable_len, (shfs_vol.htable_len * shfs_vol.chunksize) / 1024,
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

	/* shell commands */
	ret = shell_register_cmd("mount", shcmd_shfs_mount);
	if (ret < 0)
		return ret;
	ret = shell_register_cmd("umount", shcmd_shfs_umount);
	if (ret < 0)
		return ret;
	ret = shell_register_cmd("ls", shcmd_shfs_ls);
	if (ret < 0)
		return ret;
	ret = shell_register_cmd("file", shcmd_shfs_file);
	if (ret < 0)
		return ret;
	ret = shell_register_cmd("df", shcmd_shfs_dumpfile);
	if (ret < 0)
		return ret;
	ret = shell_register_cmd("cat", shcmd_shfs_cat);
	if (ret < 0)
		return ret;
#ifdef SHFS_STATS
	ret = shell_register_cmd("stats", shcmd_shfs_stats);
	if (ret < 0)
		return ret;
#endif
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

void hash_unparse(const hash512_t h, uint8_t hlen, char *out)
{
	uint8_t i;

	for (i = 0; i < hlen; i++)
		snprintf(out + (2*i), 3, "%02x", h[i]);
}

size_t strftimestamp_s(char *s, size_t slen, const char *fmt, uint64_t ts_sec)
{
	struct tm *tm;
	time_t *tsec = (time_t *) &ts_sec;
	tm = localtime(tsec);
	return strftime(s, slen, fmt, tm);
}
