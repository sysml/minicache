#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <getopt.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>

#include <uuid/uuid.h>

#include "shfs_mkfs.h"

unsigned int verbosity = 0;
int force = 0;

/******************************************************************************
 * ARGUMENT PARSING                                                           *
 ******************************************************************************/
const char *short_opts = "h?vVfn:s:b:e:";

static struct option long_opts[] = {
	{"help",		no_argument,		NULL,	'h'},
	{"version",		no_argument,		NULL,	'V'},
	{"verbose",		no_argument,		NULL,	'v'},
	{"force",		no_argument,		NULL,	'f'},
	{"name",		required_argument,	NULL,	'n'},
	{"stripesize",		required_argument,	NULL,	's'},
	{"bucket-count",	required_argument,	NULL,	'b'},
	{"entries-per-bucket",	required_argument,	NULL,	'e'},
	{NULL, 0, NULL, 0} /* end of list */
};

static inline void print_version()
{
	printf("%s (build: %s %s)\n", STR_VERSION, __DATE__, __TIME__);
}

static void print_usage(char *argv0)
{
	printf("Usage: %s [OPTION]... [DEVICE]...\n", argv0);
	printf("Formats a device with SHFS.\n");
	printf("\n");
	printf("Mandatory arguments to long options are mandatory for short options too.\n");
	printf("\n");
	printf(" General option:\n");
	printf("  -h, --help                       displays this help and exit\n");
	printf("  -V, --version                    displays program version and exit\n");
	printf("  -v, --verbose                    increases verbosity level (max. %d times)\n", D_MAX);
	printf("  -f, --force                      suppresses user questions\n");
	printf("\n");
	printf(" Volume settings:\n");
	printf("  -n, --name [NAME]                sets volume name to NAME\n");
	printf("  -s, --stripesize [BYTES]         sets the stripesize for each volume member\n");
	printf("\n");
	printf(" Hash table related configuration:\n");
	printf("  -b, --bucket-count [COUNT]       sets the total number of buckets\n");
	printf("  -e, --entries-per-bucket [COUNT] sets the number of entries for each bucket\n");
}

static inline void release_args(struct args *args)
{
	memset(args, 0, sizeof(*args));
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
	int tmp, ret;

	/*
	 * set default values
	 */
	args->volname[0]  = 'u';
	args->volname[1]  = 'n';
	args->volname[2]  = 'n';
	args->volname[3]  = 'a';
	args->volname[4]  = 'm';
	args->volname[5]  = 'e';
	args->volname[6]  = 'd';
	args->volname[7]  = '\0';
	args->volname[17] = '\0';
	args->stripesize = 4096;
	args->allocator = SALLOC_FIRSTFIT;
	args->bucket_count = 4096;
	args->entries_per_bucket = 16;

	args->hashfunc = SHFUNC_SHA;
	args->hashlen = 32; /* 256 bits */

	/*
	 * Parse options
	 */
	while (1) {
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
			force = 1;
			break;
		case 'n': /* name */
			strncpy(args->volname, optarg, sizeof(args->volname) - 1);
			break;
		case 's': /* stripesize */
			ret = parse_args_setval_int(&tmp, optarg);
			if (ret < 0 ||
			    tmp < 4096 ||
			    !POWER_OF_2(tmp) ||
			    tmp > 32768) {
				eprintf("Invalid stripe size (min. 4096, max. 32768, and has to be a power of two)\n");
				return -EINVAL;
			}
			args->stripesize = (uint32_t) tmp;
			break;
		case 'b': /* bucket-count */
			ret = parse_args_setval_int(&tmp, optarg);
			if (ret < 0 || tmp < 1) {
				eprintf("Invalid bucket count (min. 1)\n");
				return -EINVAL;
			}
			args->bucket_count = (uint32_t) tmp;
			break;
		case 'e': /* entries-per-bucket */
			ret = parse_args_setval_int(&tmp, optarg);
			if (ret < 0 || tmp < 1) {
				eprintf("Invalid number of entries per bucket (min. 1)\n");
				return -EINVAL;
			}
			args->entries_per_bucket = (uint32_t) tmp;
			break;
		default:
			/* unknown option */
			return -EINVAL;
		}
	}

	/* bucket/entry overflow check */
	if (((uint64_t) args->bucket_count) * ((uint64_t) args->entries_per_bucket) > UINT32_MAX) {
		printf("Combination of bucket count and entries per bucket leads to unsupported hash table size\n");
		return -EINVAL;
	}

	/* extra arguments are devices... just add a reference of those to args */
	if (argc <= optind) {
		eprintf("Path to device(s) not specified\n");
		return -EINVAL;
	}
	args->devpath = &argv[optind];
	args->nb_devs = argc - optind;

	return 0;
}

/******************************************************************************
 * SIGNAL HANDLING                                                            *
 ******************************************************************************/

static volatile int cancel = 0;

void sigint_handler(int signum) {
	printf("Caught abort signal: Cancelling...\n");
	cancel = 1;
}

/******************************************************************************
 * MAIN                                                                       *
 ******************************************************************************/
static void mkfs(struct disk *d, struct args *args)
{
	int ret;
	void *chk0;
	void *chk0_zero;
	void *chk1;
	off_t htable_base;
	off_t htable_bak_base;
	off_t hentry_offset;
	struct shfs_hdr_common *hdr_common;
	struct shfs_hdr_config *hdr_config;
	struct shfs_hentry     *hentry;
	uint32_t nb_hentries_per_chk;
	uint32_t nb_hentries;
	uint32_t i;
	uint32_t status_i;
	uint64_t mdata_size;
	uint64_t chunksize;

	/*
	 * Fillout headers / init entries
	 */
	chk0      = calloc(1, 4096);
	chk0_zero = calloc(1, 4096);
	chk1      = calloc(1, (size_t) args->stripesize);
	hentry    = calloc(1, sizeof(*hentry));
	if (!chk0 || !chk0_zero || !chk1 || !hentry)
		die();

	/* chunk0: common header */
	hdr_common = chk0 + BOOT_AREA_LENGTH;
	hdr_common->magic[0] = SHFS_MAGIC0;
	hdr_common->magic[1] = SHFS_MAGIC1;
	hdr_common->magic[2] = SHFS_MAGIC2;
	hdr_common->magic[3] = SHFS_MAGIC3;
	hdr_common->version[0] = SHFSv1_VERSION0;
	hdr_common->version[1] = SHFSv1_VERSION1;
	uuid_generate(hdr_common->vol_uuid);
	strncpy(hdr_common->vol_name, args->volname, 16);
#if __BYTE_ORDER == __LITTLE_ENDIAN
	hdr_common->vol_byteorder = SBO_LITTLEENDIAN;
#elif __BYTE_ORDER == __BIG_ENDIAN
	hdr_common->vol_byteorder = SBO_BIGENDIAN;
#else
#warning "Could not detect byte-order"
#endif
	hdr_common->vol_encoding = SENC_UNSPECIFIED;
	hdr_common->vol_creation_ts = 0; /* TO BE DONE */

	/* setup striping as single disk, only */
	uuid_generate(hdr_common->member_uuid);
	hdr_common->member_count = 1;
	hdr_common->member_stripesize = args->stripesize;
	uuid_copy(hdr_common->member[0].uuid, hdr_common->member_uuid);

	/* calculate volume and chunk size */
	chunksize = SHFS_CHUNKSIZE(hdr_common);
	hdr_common->vol_size = (chk_t) (d->size / chunksize);

	/* chunk1: config header */
	hdr_config = chk1;
	hdr_config->htable_ref = 2;
	hdr_config->htable_bak_ref = 0; /* disable htable backup */
	hdr_config->hfunc = args->hashfunc;
	hdr_config->hlen = args->hashlen;
	hdr_config->htable_bucket_count = args->bucket_count;
	hdr_config->htable_entries_per_bucket = args->entries_per_bucket;
	hdr_config->allocator = args->allocator;

	/* hentry defaults */
	/* NONE: everything zero'ed */

	/*
	 * Check
	 */
	mdata_size = CHUNKS_TO_BYTES(metadata_size(hdr_common, hdr_config), chunksize);
	if (mdata_size > d->size)
		dief("%s is to small: Disk label requires %ld Bytes but only %ld Bytes are available\n",
		     d->path, mdata_size, d->size);

	/*
	 * Summary
	 */
	if (cancel)
		exit(-2);
	print_shfs_hdr_summary(hdr_common, hdr_config);
	if (!force) {
		char *rlin = NULL;
		size_t n = 2;
		int num_rlin_bytes;

		printf("\n");
		printf("Shall this label be written to the device?\n");
		printf("Be warned that all existing data will be lost!\n");
		printf("Continue? [yN] ");
		num_rlin_bytes = getline(&rlin, &n, stdin);

		if (num_rlin_bytes < 0)
			die();
		if (rlin[0] != 'y' && rlin[0] != 'Y') {
			printf("Aborted\n");
			exit(EXIT_SUCCESS);
		}

		if (rlin)
			free(rlin);
	}
	if (cancel)
		exit(-2);
	printf("\n");

	/*
	 *
	 */
	printf("Erasing common header area...\n");
	ret = lseek(d->fd, 0, SEEK_SET);
	if (ret < 0)
		die();
	if (cancel)
		exit(-2);
	ret = write(d->fd, chk0_zero, chunksize);
	if (ret < 0)
		die();

	/*
	 * Write htable entries
	 */
	nb_hentries = hdr_config->htable_entries_per_bucket * hdr_config->htable_bucket_count;
	htable_base = CHUNKS_TO_BYTES(hdr_config->htable_ref, chunksize);
	htable_bak_base = CHUNKS_TO_BYTES(hdr_config->htable_ref, chunksize);
	nb_hentries_per_chk = SHFS_HENTRIES_PER_CHUNK(chunksize);
	status_i = 64;
	if (verbosity == D_MAX)
		status_i = 1;

	for (i = 0; i < nb_hentries; i++) {
		if (cancel)
			exit(-2);

		hentry_offset = htable_base + \
			CHUNKS_TO_BYTES(SHFS_HTABLE_CHUNK_NO(i, nb_hentries_per_chk), chunksize) + \
			SHFS_HTABLE_ENTRY_OFFSET(i, nb_hentries_per_chk);
		if (i % status_i == 0) {
			printf("\rWriting table entries... [%ld/%ld]", i, nb_hentries);
			dprintf(D_L0, " (@0x%08x)", hentry_offset);
			fflush(stdout);
		}
		ret = lseek(d->fd, hentry_offset, SEEK_SET);
		if (ret < 0)
			die();
		ret = write(d->fd, hentry, sizeof(*hentry));
		if (ret < 0)
			die();

	}
	printf("\rWriting table entries... [%ld/%ld]                   \n",
	       nb_hentries, nb_hentries);

	if (hdr_config->htable_bak_ref) {
		printf("\n");
		for (i = 0; i < nb_hentries; i++) {
			if (cancel)
				exit(-2);

			hentry_offset = htable_bak_base + \
				CHUNKS_TO_BYTES(SHFS_HTABLE_CHUNK_NO(i, nb_hentries_per_chk), chunksize) + \
				SHFS_HTABLE_ENTRY_OFFSET(i, nb_hentries_per_chk);
			if (i % status_i == 0) {
				printf("\rWriting backup table entries... [%ld/%ld]",  i, nb_hentries);
				dprintf(D_L0, " (@0x%08x)", hentry_offset);
				fflush(stdout);
			}
			ret = lseek(d->fd, hentry_offset, SEEK_SET);
			if (ret < 0)
				die();
			ret = write(d->fd, hentry, sizeof(*hentry));
			if (ret < 0)
				die();
		}
		printf("\rWriting backup table entries... [%ld/%ld]                   \n",
		       nb_hentries, nb_hentries);
	}

	/*
	 * Write headers
	 */
	if (cancel)
		exit(-2);
	printf("Writing config header...\n");
	ret = lseek(d->fd, chunksize, SEEK_SET);
	if (ret < 0)
		die();
	ret = write(d->fd, chk1, chunksize);
	if (ret < 0)
		die();

	if (cancel)
		exit(-2);
	printf("Writing common header...\n");
	ret = lseek(d->fd, 0, SEEK_SET);
	if (ret < 0)
		die();
	ret = write(d->fd, chk0, chunksize);
	if (ret < 0)
		die();

	free(hentry);
	free(chk1);
	free(chk0_zero);
	free(chk0);
}

int main(int argc, char **argv)
{
	struct args args;
	struct disk *d;

	signal(SIGINT,  sigint_handler);
	signal(SIGTERM, sigint_handler);
	signal(SIGQUIT, sigint_handler);

	/*
	 * ARGUMENT PARSING
	 */
	memset(&args, 0, sizeof(args));
	if (parse_args(argc, argv, &args) < 0)
		exit(EXIT_FAILURE);
	if (verbosity > 0) {
		fprintf(stderr, "Verbosity increased to level %d.\n", verbosity);
	}
	printvar(args.nb_devs, "%u");
	printvar(args.encoding, "%d");
	printvar(args.volname, "%s");
	printvar(args.stripesize, "%ld");

	printvar(args.hashfunc, "%d");
	printvar(args.allocator, "%d");
	printvar(args.hashlen, "%ld");
	printvar(args.bucket_count, "%ld");
	printvar(args.entries_per_bucket, "%ld");

	/*
	 * MAIN
	 */
	if (args.nb_devs > 1) {
		printf("Sorry, multi-member volume format is not supported yet.\n");
		exit(EXIT_FAILURE);
	}
	d = open_disk(args.devpath[0], O_RDWR);
	if (!d)
		exit(EXIT_FAILURE);
	if (cancel)
		exit(-2);
	mkfs(d, &args);
	close_disk(d);

	/*
	 * EXIT
	 */
	release_args(&args);
	exit(EXIT_SUCCESS);
}
