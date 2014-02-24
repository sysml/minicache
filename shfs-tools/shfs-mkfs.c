#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <getopt.h>
#include <unistd.h>
#include <fcntl.h>

#include <uuid/uuid.h>

#include "shfs-mkfs.h"

unsigned int verbosity = 0;
bool force = false;

/******************************************************************************
 * ARGUMENT PARSING                                                           *
 ******************************************************************************/
const char *short_opts = "h?vVf";

static struct option long_opts[] = {
	{"help",	no_argument,		NULL,	'h'},
	{"version",	no_argument,		NULL,	'V'},
	{"verbose",	no_argument,		NULL,	'v'},
	{"force",	no_argument,		NULL,	'f'},
	{NULL, 0, NULL, 0} /* end of list */
};

static inline void print_version()
{
	printf("%s (build: %s %s)\n", STR_VERSION, __DATE__, __TIME__);
}

static void print_usage(char *argv0)
{
	printf("Usage: %s [OPTION]... [DEVICE]\n", argv0);
	printf("Formats a device with SHFS.\n");
	printf("\n");
	printf("Mandatory arguments to long options are mandatory for short options too.\n");
	printf("  -h, --help                 display this help and exit\n");
	printf("  -V, --version              display program version and exit\n");
	printf("  -v, --verbose              increase verbosity level (max. %d times)\n", D_MAX);
	printf("  -f, --force                Suppress warnings and user questions\n");
}

static inline void release_args(struct args *args)
{
	if (args->devpath)
		free(args->devpath);
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
	int ret;

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
	args->chunksize = 4096;
	args->allocator = SALLOC_BESTFIT;
	args->hashfunc = SHFUNC_SHA1;
	args->hashlen = 8; /* 512 bits */
	args->bucket_count = 2048;
	args->entries_per_bucket = 16;

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
		default:
			eprintf("Unrecognized option\n");
			return -EINVAL;
			/* unknown option */
		}
	}

	/* extra parameter available? */
	if (argc <= optind) {
		eprintf("Path to device not specified\n");
		return -EINVAL;
	}
	parse_args_setval_str(&args->devpath, argv[optind]);

	return 0;
}


/******************************************************************************
 * MAIN                                                                       *
 ******************************************************************************/
static void mkfs(struct disk *d, struct args *args)
{
	uuid_t uu_d, uu_vol;
	void * chk0;
	void * chk1;
	struct shfs_hdr_common *hdr_common;
	struct shfs_hdr_config *hdr_config;
	struct shfs_hentry     *hentry;
	size_t hentry_len;
	uint32_t nb_hentries_per_chk;
	uint32_t nb_hentries;
	uint32_t i;

	/*
	 * Fillout headers / init entries
	 */
	chk0 = calloc(1, (size_t) args->chunksize);
	chk1 = calloc(1, (size_t) args->chunksize);
	hentry = calloc(1, sizeof(*hentry));
	if (!chk0 || !chk1 || !hentry)
		die();
	hentry_len = SHFS_HENTRY_SIZE(args->chunksize);

	/* chunk0 */
	hdr_common = chk0 + BOOT_AREA_LENGTH;
	hdr_common->magic[0] = SHFS_MAGIC0;
	hdr_common->magic[1] = SHFS_MAGIC1;
	hdr_common->magic[2] = SHFS_MAGIC2;
	hdr_common->magic[3] = SHFS_MAGIC3;
	hdr_common->version[0] = SHFSv1_VERSION0;
	hdr_common->version[1] = SHFSv1_VERSION1;
	uuid_generate(uu_vol);
	for (i = 0; i < 16; i++)
		hdr_common->vol_uuid[i] = uu_vol[i];
	strncpy(hdr_common->vol_name, args->volname, 16);
#if __BYTE_ORDER == __LITTLE_ENDIAN
	hdr_common->vol_byteorder = SBO_LITTLEENDIAN;
#elif __BYTE_ORDER == __BIG_ENDIAN
	hdr_common->vol_byteorder = SBO_BIGENDIAN;
#else
#warning "Could not detected byte-order"
#endif
	hdr_common->vol_encoding = SENC_UNSPECIFIED;
	hdr_common->vol_chunksize = args->chunksize;
	hdr_common->vol_size = (chk_t) (d->size / (uint64_t) args->chunksize);
	hdr_common->vol_creation_ts = 0; /* TO BE DONE */

	/* setup striping as single disk, only */
	uuid_generate(uu_d);
	for (i = 0; i < 16; i++)
		hdr_common->member_uuid[i] = uu_d[i];
	hdr_common->member_count = 1;
	hdr_common->member_stripe_size = args->chunksize;
	for (i = 0; i < 16; i++)
		hdr_common->member[0].uuid[i] = uu_d[i];

	/* chunk1 */
	hdr_config = chk1;
	hdr_config->htable_ref = 2;
	hdr_config->htable_bak_ref = 0; /* disable htable backup */
	hdr_config->hfunc = args->hashfunc;
	hdr_config->hlen = args->hashlen;
	hdr_config->htable_bucket_count = args->bucket_count;
	hdr_config->htable_entries_per_bucket = args->entries_per_bucket;
	hdr_config->allocator = args->allocator;

	/* hentry */
	/* NONE */

	/*
	 * Check
	 */
	if (min_disk_size(hdr_common, hdr_config) > d->size)
		dief("%s is to small: %ld Bytes required but %ld Bytes available\n",
		     args->devpath, min_disk_size(hdr_common, hdr_config), d->size);

	/*
	 * Summary
	 */
	print_shfs_hdr_summary(hdr_common, hdr_config);
	if (!force) {
		char *rlin;
		size_t n = 2;
		int num_rlin_bytes;

		printf("Warning: Existing data will be lost!\n");
		printf("Continue and write to disk? [yN] ");
		num_rlin_bytes = getline(&rlin, &n, stdin);

		if (num_rlin_bytes < 0)
			die();
		if (rlin[0] != 'y' && rlin[0] != 'Y') {
			printf("Aborted\n");
			exit(EXIT_SUCCESS);
		}
	}
	printf("\n");

	/*
	 * Write htable entries
	 */
	nb_hentries = hdr_config->htable_entries_per_bucket * hdr_config->htable_bucket_count;
	printf("Writing table entries... [%ld/%ld]", 0, nb_hentries);
	fflush(stdout);
	lseek(d->fd, (hdr_common->vol_chunksize * hdr_config->htable_ref), SEEK_SET);
	for (i = 0; i < nb_hentries; i++) {
		if (i % 64 == 0) {
			printf("\rWriting table entries... [%ld/%ld]", i, nb_hentries);
			fflush(stdout);
		}
		write(d->fd, hentry, sizeof(*hentry));
		lseek(d->fd, hentry_len - sizeof(*hentry), SEEK_CUR);
	}
	printf("\rWriting table entries... [%ld/%ld]\n", nb_hentries, nb_hentries);

	/*
	 * Write headers
	 */
	printf("Writing config header...\n");
	lseek(d->fd, hdr_common->vol_chunksize, SEEK_SET);
	write(d->fd, chk1, hdr_common->vol_chunksize);

	printf("Writing common header...\n");
	lseek(d->fd, 0, SEEK_SET);
	write(d->fd, chk0, hdr_common->vol_chunksize);
}

int main(int argc, char **argv)
{
	struct args args;
	struct disk *d;

	/*
	 * ARGUMENT PARSING
	 */
	memset(&args, 0, sizeof(args));
	if (parse_args(argc, argv, &args) < 0)
		exit(EXIT_FAILURE);
	if (verbosity > 0) {
		fprintf(stderr, "Verbosity increased to level %d.\n", verbosity);
	}
	printvar(args.devpath, "%s");
	printvar(args.encoding, "%d");
	printvar(args.volname, "%s");
	printvar(args.chunksize, "%ld");

	printvar(args.hashfunc, "%d");
	printvar(args.allocator, "%d");
	printvar(args.hashlen, "%ld");
	printvar(args.bucket_count, "%ld");
	printvar(args.entries_per_bucket, "%ld");


	/*
	 * MAIN
	 */
	d = open_disk(args.devpath, O_RDWR);
	if (!d)
		exit(EXIT_FAILURE);
	mkfs(d, &args);
	close_disk(d);

	/*
	 * EXIT
	 */
	release_args(&args);
	exit(EXIT_SUCCESS);
}
