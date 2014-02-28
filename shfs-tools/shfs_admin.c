#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <getopt.h>
#include <unistd.h>
#include <fcntl.h>

#include <uuid/uuid.h>

#include "shfs_admin.h"
#include "shfs_htable.h"

unsigned int verbosity = 0;
bool force = false;

static struct vol_info shfs_vol;

/******************************************************************************
 * ARGUMENT PARSING                                                           *
 ******************************************************************************/
const char *short_opts = "h?vVfa:";

static struct option long_opts[] = {
	{"help",	no_argument,		NULL,	'h'},
	{"version",	no_argument,		NULL,	'V'},
	{"verbose",	no_argument,		NULL,	'v'},
	{"force",	no_argument,		NULL,	'f'},
	{"add-file",	required_argument,	NULL,	'a'},
	{NULL, 0, NULL, 0} /* end of list */
};

static inline void print_version()
{
	printf("%s (build: %s %s)\n", STR_VERSION, __DATE__, __TIME__);
}

static void print_usage(char *argv0)
{
	printf("Usage: %s [OPTION]... [DEVICE]...\n", argv0);
	printf("Administration of an SHFS volume.\n");
	printf("\n");
	printf("Mandatory arguments to long options are mandatory for short options too.\n");
	printf("  -h, --help                 display this help and exit\n");
	printf("  -V, --version              display program version and exit\n");
	printf("  -v, --verbose              increase verbosity level (max. %d times)\n", D_MAX);
	printf("  -f, --force                Suppress warnings and user questions\n");
	printf("  -a, --add-file [FILE]      Add a file to the volume\n");
	printf("  -r, --rm-file [HASH]       Remove a file from the volume\n");
	printf("\n");
	printf("Example (adding a file):\n");
	printf(" %s --add-file song.mp4 /dev/ram14 /dev/ram15\n");

}

static void release_args(struct args *args)
{
	struct job *cjob;
	struct job *njob;

	cjob = args->jobs;

	/* release job list */
	while (cjob) {
		njob = cjob->next;
		free(cjob);
		cjob = njob;
	}
	memset(args, 0, sizeof(*args));
}

/**
 * Adds a job to args job list
 *
 * ljob: Current last job of the list
 *       If it is NULL, it is assumed that there is no list currently
 *       -> this function creates the first element and adds it to args
 */
static inline struct job *args_add_job(struct job *ljob, struct args *args)
{
	struct job *njob;

	njob = calloc(1, sizeof(*njob));
	if (!njob)
		die();

	if (ljob)
		ljob->next = njob;
	else
		args->jobs = njob;

	return njob;
}

static int parse_args(int argc, char **argv, struct args *args)
/*
 * Parse arguments on **argv (number of args on argc)
 * with GNUOPTS to *args
 *
 * This function will exit the program for itself
 * when -h or -V is parsed or on fatal errors
 * (such as ENOMEM)
 *
 * -EINVAL will be returned on parsing errors or
 * invalid options
 *
 * *args has to be passed in a cleared state
 */
{
	int opt, opt_index = 0;
	struct job *cjob;
	/*
	 * set default values
	 */
	args->nb_devs = 0;
	args->jobs = NULL;
	cjob = args->jobs;

	/*
	 * Parse options
	 */
	while (true) {
		opt = getopt_long(argc, argv, short_opts, long_opts, &opt_index);

		if (opt == -1)    /* end of options */
			break;

		switch (opt) {
		case 'h':
		case '?': /* usage */
			print_usage(argv[0]);
			exit(EXIT_SUCCESS);
		case 'V': /* version */
			print_version();
			exit(EXIT_SUCCESS);
		case 'v': /* verbosity */
			if (verbosity < D_MAX)
				verbosity++;
			break;
		case 'f': /* force */
			force = true;
			break;
		case 'a': /* add-file */
			cjob = args_add_job(cjob, args);
			cjob->action = ADDFILE;
			if (parse_args_setval_str(&cjob->path, argv[optind]) < 0)
				die();
		default:
			eprintf("Unrecognized option\n");
			return -EINVAL;
			/* unknown option */
		}
	}

	/* extra arguments are devices... just add a reference of those to args */
	if (argc <= optind) {
		eprintf("Path to device(s) not specified\n");
		return -EINVAL;
	}
	args->devpath = &argv[optind];
	args->nb_devs = argc - optind;

	/* check job list, if mandatory argements were given */
	for (cjob = args->jobs; cjob != NULL; cjob = cjob->next) {
		switch(cjob->action) {
		case ADDFILE:
			/* nothing to check (mime is optional) */
			break;
		default:
			dief("Unsupported job found"); /* should never happen */
		}

		cjob = cjob->next;
	}

	return 0;
}

/******************************************************************************
 * DISK I/O                                                                   *
 ******************************************************************************/
/**
 * Performs I/O on the member disks of a volume
 *
 * This function can only be called, after load_vol_cconf
 * established successfully the low-level setup of a volume
 */
static int shfs_sync_io_chunk(chk_t start, chk_t len, int owrite, void *buffer)
{
	chk_t end, c;
	off_t startb;
	size_t lenb;
	unsigned int m;
	uint8_t *wptr = buffer;

	end = start + len;
	for (c = start; c < end; c++) {
		for (m = 0; m < shfs_vol.nb_members; ++m) {
			startb = c * shfs_vol.stripesize;
			lenb = shfs_vol.stripesize;
			dprintf(D_L1, "blkdev_sync_io member=%u, start=%lub, len=%lub, wptr=%p\n",
			       m, startb, lenb, wptr);

			if (lseek(shfs_vol.member[m].d->fd, startb, SEEK_SET) < 0) {
				eprintf("Could not seek on %s: %s\n", shfs_vol.member[m].d->path, strerror(errno));
				return -1;
			}
			if (owrite) {
				if (write(shfs_vol.member[m].d->fd, wptr, shfs_vol.stripesize) < 0) {
					eprintf("Could not write to %s: %s\n", shfs_vol.member[m].d->path, strerror(errno));
					return -1;
				}
			} else {
				if (read(shfs_vol.member[m].d->fd, wptr, shfs_vol.stripesize) < 0) {
					eprintf("Could not read from %s: %s\n", shfs_vol.member[m].d->path, strerror(errno));
					return -1;
				}
			}

			wptr += shfs_vol.stripesize;
		}
	}

	return 0;
}
#define shfs_sync_read_chunk(start, len, buffer) \
	shfs_sync_io_chunk((start), (len), 0, (buffer))
#define shfs_sync_write_chunk(start, len, buffer) \
	shfs_sync_io_chunk((start), (len), 1, (buffer))


/******************************************************************************
 * MAIN                                                                       *
 ******************************************************************************/
/**
 * This function tries to open a blkdev and checks if it has a valid SHFS label
 * It returns the opened blkdev descriptor and the read disk chk0
 *  on *chk0
 *
 * Note: chk0 has to be a buffer of 4096 bytes and be aligned to 4096 bytes
 */
static struct disk *checkopen_disk(const char *path, void *chk0)
{
	struct disk *d;
	int ret;

	d = open_disk(path, O_RDWR);
	if (!d)
		dief("Could not open %s\n", path);

	/* incompatible device? */
	if (d->blksize < 512 || !POWER_OF_2(d->blksize))
		dief("%s has a incompatible block size\n", path);

	/* read first chunk (considered as 4K) */
	if (lseek(d->fd, 0, SEEK_SET) < 0)
		dief("Could not seek on %s: %s\n", path, strerror(errno));

	if (read(d->fd, chk0, 4096) < 0)
		dief("Could not read from %s: %s\n", path, strerror(errno));

	/* Try to detect the SHFS disk label */
	ret = shfs_detect_hdr0(chk0);
	if (ret < 0)
		dief("Invalid or unsupported SHFS label detected on %s: %d\n", path, ret);

	return d;
}

/**
 * This function iterates over disks, tries to detect the SHFS label
 * and does the low-level setup for mounting a volume
 */
static void load_vol_cconf(char *path[], unsigned int count)
{
	struct disk *d;
	struct vol_member detected_member[MAX_NB_TRY_BLKDEVS];
	struct shfs_hdr_common *hdr_common;
	unsigned int i, j, m;
	unsigned int nb_detected_members;
	uint64_t min_member_size;
	void *chk0;

	dprintf(D_L0, "Detecting SHFS volume...\n");
	if (count > MAX_NB_TRY_BLKDEVS)
		dief("More devices passed than supported by a single SHFS volume");

	chk0 = malloc(4096);
	if (!chk0)
		die();

	/* Iterate over disks and try to find those with a valid SHFS disk label */
	nb_detected_members = 0;
	for (i = 0; i < count; i++) {
		d = checkopen_disk(path[i], chk0);
		dprintf(D_L0, "SHFSv1 label on %s detected\n", path[i]);

		/* chk0 contains the first chunk read from disk */
		hdr_common = (void *)((uint8_t *) chk0 + BOOT_AREA_LENGTH);
		detected_member[nb_detected_members].d = d;
		uuid_copy(detected_member[nb_detected_members].uuid, hdr_common->member_uuid);
		nb_detected_members++;
	}
	if (nb_detected_members == 0)
		dief("No SHFS disk found");

	/* Load label from first detected member */
	/* read first chunk (considered as 4K) */
	if (lseek(detected_member[0].d->fd, 0, SEEK_SET) < 0)
		dief("Could not seek on %s: %s\n", detected_member[0].d->path, strerror(errno));
	if (read(detected_member[0].d->fd, chk0, 4096) < 0)
		dief("Could not read from %s: %s\n", detected_member[0].d->path, strerror(errno));

	hdr_common = (void *)((uint8_t *) chk0 + BOOT_AREA_LENGTH);
	memcpy(shfs_vol.uuid, hdr_common->vol_uuid, 16);
	memcpy(shfs_vol.volname, hdr_common->vol_name, 16);
	shfs_vol.volname[17] = '\0'; /* ensure nullterminated volume name */
	shfs_vol.stripesize = hdr_common->member_stripesize;
	shfs_vol.chunksize = SHFS_CHUNKSIZE(hdr_common);
	shfs_vol.volsize = hdr_common->vol_size;

	/* Find and add members to the volume */
	shfs_vol.nb_members = 0;
	for (i = 0; i < hdr_common->member_count; i++) {
		for (m = 0; m < nb_detected_members; ++m) {
			if (uuid_compare(hdr_common->member[i].uuid, detected_member[m].uuid) == 0) {
				/* found device but was this member already added (malformed label)? */
				for (j = 0; j < shfs_vol.nb_members; ++j) {
					if (uuid_compare(shfs_vol.member[j].uuid,
					                 hdr_common->member[i].uuid) == 0)
						dief("A member is specified for multiple times for volume '%s'\n",
						     shfs_vol.volname);
				}
				shfs_vol.member[shfs_vol.nb_members].d = detected_member[m].d;
				uuid_copy(shfs_vol.member[shfs_vol.nb_members].uuid, detected_member[m].uuid);
				shfs_vol.nb_members++;
				continue;
			}
		}

	}
	if (shfs_vol.nb_members != count)
		dief("More members specified than actually required for volume '%s'\n", shfs_vol.volname);
	if (shfs_vol.nb_members != hdr_common->member_count)
		dief("Could not establish member mapping for volume '%s'\n", shfs_vol.volname);

	/* chunk and stripe size -> retrieve a device sector factor for each device */
	if (shfs_vol.stripesize < 4096 || !POWER_OF_2(shfs_vol.stripesize))
		dief("Stripe size invalid on volume '%s'\n", shfs_vol.volname);

	/* calculate and check volume size */
	min_member_size = (shfs_vol.volsize / shfs_vol.nb_members) * (uint64_t) shfs_vol.chunksize;
	for (i = 0; i < shfs_vol.nb_members; ++i) {
		if (shfs_vol.member[i].d->size < min_member_size)
			dief("Member %u of volume '%s' is too small\n", i, shfs_vol.volname);
	}

	free(chk0);
}

/**
 * This function loads the hash configuration from chunk 1
 * (as defined in SHFS)
 * This function can only be called, after load_vol_cconf
 * established successfully the low-level setup of a volume
 * (required for chunk I/O)
 */
static void load_vol_hconf(void)
{
	struct shfs_hdr_config *hdr_config;
	void *chk1;
	int ret;

	chk1 = malloc(shfs_vol.chunksize);
	if (!chk1)
		die();

	dprintf(D_L0, "Load SHFS configuration chunk\n");
	ret = shfs_sync_read_chunk(1, 1, chk1);
	if (ret < 0)
		die();

	hdr_config = chk1;
	shfs_vol.htable_ref                   = hdr_config->htable_ref;
	shfs_vol.htable_bak_ref               = hdr_config->htable_bak_ref;
	shfs_vol.htable_nb_buckets            = hdr_config->htable_bucket_count;
	shfs_vol.htable_nb_entries_per_bucket = hdr_config->htable_entries_per_bucket;
	shfs_vol.htable_nb_entries            = SHFS_HTABLE_NB_ENTRIES(hdr_config);
	shfs_vol.htable_nb_entries_per_chunk  = SHFS_HENTRIES_PER_CHUNK(shfs_vol.chunksize);
	shfs_vol.htable_len                   = SHFS_HTABLE_SIZE_CHUNKS(hdr_config, shfs_vol.chunksize);
	shfs_vol.hlen = hdr_config->hlen;
	ret = 0;

	free(chk1);
}

/**
 * This function loads the hash table from the block device into memory
 * Note: load_vol_hconf() and local_vol_cconf() has to called before
 */
static void load_vol_htable(void)
{
	struct shfs_hentry *hentry;
	struct shfs_bentry *bentry;
	void *tmp_chk;
	chk_t tmp_chk_addr, cur_chk;
	unsigned int i;
	int ret;

	/* allocate bucket table */
	dprintf(D_L0, "Allocating btable...\n");
	shfs_vol.bt = shfs_alloc_btable(shfs_vol.htable_nb_buckets,
	                                shfs_vol.htable_nb_entries_per_bucket,
	                                shfs_vol.hlen);
	if (!shfs_vol.bt)
		die();

	/* allocate chunk cache reference table */
	dprintf(D_L0, "Allocating chunk cache reference table...\n");
	shfs_vol.htable_chunk_cache = calloc(1, sizeof(void *) * shfs_vol.htable_len);
	if (!shfs_vol.htable_chunk_cache)
		die();

	/* load hash table chunk-wise and fill-out btable metadata */
	tmp_chk = malloc(shfs_vol.chunksize);
	if (!tmp_chk)
		die();

	tmp_chk_addr = 0;
	for (i = 0; i < shfs_vol.htable_nb_entries; ++i) {
		cur_chk = shfs_vol.htable_ref + \
			  SHFS_HTABLE_CHUNK_NO(i, shfs_vol.htable_nb_entries_per_chunk);
		if (tmp_chk_addr != cur_chk) {
			ret = shfs_sync_read_chunk(cur_chk, 1, tmp_chk);
			if (ret < 0)
				dief("An error occured while reading the hash table from the volume\n");
			tmp_chk_addr = cur_chk;
		}

		bentry = shfs_btable_pick(shfs_vol.bt, i);
		bentry->chunk = cur_chk;
		bentry->offset = SHFS_HTABLE_ENTRY_OFFSET(i, shfs_vol.htable_nb_entries_per_chunk);
		hentry = (struct shfs_hentry *)((uint8_t *) tmp_chk + bentry->offset);
		hash_copy(bentry->hash, hentry->hash, shfs_vol.hlen);
	}
	free(tmp_chk);
}

/**
 * Mount a SHFS volume
 * The volume is searched on the given list of VBD
 */
void mount_shfs(char *path[], unsigned int count)
{
	if (count == 0)
		dief("No devices passed\n");

	/* load common volume information and open devices */
	load_vol_cconf(path, count);

	/* load hash conf (uses shfs_sync_read_chunk) */
	load_vol_hconf();

	/* load htable (uses shfs_sync_read_chunk) */
	load_vol_htable();
}

/**
 * Unmounts a previously mounted SHFS volume
 */
void umount_shfs(void) {
	unsigned int i;

	/* TODO: Write changed chunk caches to disk */
	free(shfs_vol.htable_chunk_cache);
	shfs_free_btable(shfs_vol.bt);
	for(i = 0; i < shfs_vol.nb_members; ++i)
		close_disk(shfs_vol.member[i].d);
}

int main(int argc, char **argv)
{
	struct args args;
	struct job *cjob;

	/*
	 * ARGUMENT PARSING
	 */
	memset(&args, 0, sizeof(args));
	if (parse_args(argc, argv, &args) < 0)
		exit(EXIT_FAILURE);
	if (verbosity > 0) {
		fprintf(stderr, "Verbosity increased to level %d.\n", verbosity);
	}

	/*
	 * MAIN
	 */
	mount_shfs(args.devpath, args.nb_devs);
	for (cjob = args.jobs; cjob != NULL; cjob = cjob->next) {
		/* do action */
	}
	umount_shfs();

	/*
	 * EXIT
	 */
	release_args(&args);
	exit(EXIT_SUCCESS);
}
