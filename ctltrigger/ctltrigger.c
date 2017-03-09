/*
 * Control Trigger Interface client for XenStore
 *
 * Authors: Simon Kuenzer <simon.kuenzer@neclab.eu>
 *
 *
 * Copyright (c) 2013-2017, NEC Europe Ltd., NEC Corporation All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * THIS HEADER MAY NOT BE EXTRACTED OR MODIFIED IN ANY WAY.
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <getopt.h>
#include <unistd.h>
#include <fcntl.h>
#include <libgen.h>
#include <signal.h>
#include <xenstore.h>

#include "ctltrigger.h"

unsigned int verbosity = 0;


/******************************************************************************
 * ARGUMENT PARSING                                                           *
 ******************************************************************************/
const char *short_opts = "h?vVn";

static struct option long_opts[] = {
	{"help",	no_argument,		NULL,	'h'},
	{"version",	no_argument,		NULL,	'V'},
	{"verbose",	no_argument,		NULL,	'v'},
	{"no-wait",	no_argument,		NULL,	'n'},
	{NULL, 0, NULL, 0} /* end of list */
};

static inline void print_version()
{
	printf("%s (build: %s %s)\n", STR_VERSION, __DATE__, __TIME__);
}

static void print_usage(char *argv0)
{
	eprintf("Usage: %s [[OPTION]...] [DOMAIN-ID] [SCOPE] -- [TRIGGER] [[ARGUMENTS]...]\n", argv0);
	eprintf(" Tiggers an ctldir action via XenStore and returns its return string to stdout\n");
	eprintf(" This command returns 0 on successful trigger execution via XenStore\n");
	eprintf(" (Note: this is independent from the return string of the action)\n");
	eprintf("\n");
	eprintf("Mandatory arguments to long options are mandatory for short options too.\n");
	eprintf("  -h, --help                 displays this help and exit\n");
	eprintf("  -V, --version              displays program version and exit\n");
	eprintf("  -v, --verbose              increases verbosity level (max. %d times)\n", D_MAX);
	eprintf("  -n, --no-wait              do not wait for ctldir lock\n");
	eprintf("\n");
	eprintf("Example (mount 51760 on MiniCache DomU 16):\n");
	eprintf(" %s 16 minicache -- mount 51760\n", argv0);

}

static void release_args(struct args *args) {
	if (args->args)
		free(args->args);
	args->args = NULL;
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
	unsigned int i;
	size_t cp_p;
	size_t arglen;

	/*
	 * set default values
	 */
	args->args = NULL;
	args->nowait = 0;

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
			exit(EXIT_SUCCESS); /* help was explicitly called */
		case 'V': /* version */
			print_version();
			exit(EXIT_SUCCESS);
		case 'v': /* verbosity */
			if (verbosity < D_MAX)
				verbosity++;
			break;
		case 'n': /* no-wait */
			args->nowait = 1;
			break;
		default:
			/* unknown option */
			return -EINVAL;
		}
	}

	/* there have to be two extra arguments: domain ID, scope; trigger is extra */
	if (argc < optind + 2) {
		print_usage(argv[0]);
		return -EINVAL;
	}

	/* domain ID */
	if (sscanf(argv[optind++], "%u", &args->domid) != 1) {
		eprintf("Invalid domain ID\n\n");
		print_usage(argv[0]);
		return -EINVAL;
	}
	/* scope */
	args->scope = argv[optind++]; /* TODO: str blank check */

	/* copy arguments after '--' to args */
	/* (concatenate them together) */
	argc -= optind;
	argv += optind;
	arglen = 0;

	args->trigger = argv[0]; /* TODO: str blank check */
	for (i = 1; i < argc; ++i)
		arglen += strlen(argv[i]) + 1;
	if (arglen) {
		args->args = malloc(arglen);
		if (!args->args) {
			eprintf("Could not parse arguments: %s\n", strerror(ENOMEM));
			return -ENOMEM;
		}
		cp_p = 0;
		for (i = 1; i < argc; ++i) {
			strcpy(&args->args[cp_p], argv[i]);
			cp_p += strlen(argv[i]);
			args->args[cp_p] = ' ';
			cp_p += 1;
		}
		args->args[cp_p - 1] = '\0';
	}

	return 0;
}


/******************************************************************************
 * SIGNAL HANDLING                                                            *
 ******************************************************************************/

static volatile int cancel = 0;

static void sigint_handler(int signum) {
	cancel = 1;
}

/******************************************************************************
 * MAIN                                                                       *
 ******************************************************************************/
#define XSBASE "/local/domain"
#define XSLOCKTOKEN "ctltrigger-client-lock-token"
#define XSTRIGGERTOKEN "ctltrigger-client-trigger-token"

static inline int ctldir_reserve_lock(struct xs_handle *xs, const char *lpath)
{
	xs_transaction_t xts;
	char *reply;
	unsigned int len;
	int lock;
	int ret;

 retry:
	dprintf(D_L1, "Initialize transaction\n");
	xts = xs_transaction_start(xs);
	if (!xts) {
		eprintf("Could not initialize a transaction");
		goto err_out;
	}

	dprintf(D_L0, "Read lock %s\n", lpath);
	reply = (char *) xs_read(xs, xts, lpath, &len);
	if (!reply || len == 0) {
		eprintf("Could not read XenStore entry %s: %s\n", lpath, strerror(errno));
	        goto err_abort_xts;
        }
	if (sscanf(reply, "%d", &lock) != 1 || lock < 0) {
		eprintf("Could not parse XenStore entry %s\n", lpath);
	        goto err_free_reply;
        }
	free(reply);

	if (lock > 0) { /* lock is held */
		dprintf(D_L0, "Lock %s is held\n", lpath);
	} else {
		dprintf(D_L0, "Lock %s is free... reserving\n", lpath);
		if (!xs_write(xs, xts, lpath, "1", 1)) {
			eprintf("Could not write to XenStore entry %s: %s\n", lpath, strerror(errno));
			goto err_abort_xts;
		}
		ret = 1;
	}

	dprintf(D_L1, "Finalize transaction\n");
	if (!xs_transaction_end(xs, xts, false)) {
		if (errno != EAGAIN) {
			eprintf("Could not finalize the transaction: %s\n", strerror(errno));
			goto err_out;
		}

		dprintf(D_L0, "Restart of transaction requested\n");
		goto retry;
	}
        return ret;

 err_free_reply:
        free(reply);
 err_abort_xts:
	dprintf(D_L1, "Abort transaction\n");
        while (!xs_transaction_end(xs, xts, true) && errno == EAGAIN)
		dprintf(D_L0, "Restart of transaction requested\n");
 err_out:
        return -1;
}

static inline int ctldir_lock(struct xs_handle *xs, unsigned int domid, const char *scope, int nowait)
{
	char path[256];
	int lock = 0;
	int cmp0, cmp1;
	int ret = 0;
	char **vec;
	unsigned int veclen;
	unsigned int ignore = 1;

	snprintf(path, sizeof(path), "%s/%u/data/%s/lock", XSBASE, domid, scope);
	if (nowait) {
		ret = ctldir_reserve_lock(xs, path);
	} else {
		dprintf(D_L1, "Watch %s\n", path);
		if (!xs_watch(xs, path, XSLOCKTOKEN)) {
			eprintf("Could not setup watch on %s\n", path);
			goto err_out;
		}

		lock = ctldir_reserve_lock(xs, path);
		if (lock < 0)
			goto err_unwatch;
		while (!lock) {
			dprintf(D_L1, "Wait for XenStore event on %s\n", path);
			vec = xs_read_watch(xs, &veclen);
			if (!vec) {
				if (errno == EAGAIN)
					continue;
				if (errno == EINTR) { /* usually signals */
					if (cancel) {
						ret = -1;
						break;
					}
					continue;
				}
				eprintf("Error while watching %s: %s\n", path, strerror(errno));
				goto err_unwatch;
			}

			dprintf(D_L1, " Event arrived: %s | %s\n",
				  vec[XS_WATCH_PATH], vec[XS_WATCH_TOKEN]);
			cmp0 = strcmp(vec[XS_WATCH_TOKEN], XSLOCKTOKEN);
			cmp1 = strcmp(vec[XS_WATCH_PATH], path);
			free(vec);
			if (cmp0 != 0 || cmp1 != 0) {
				/* some other event arrived */
				dprintf(D_L1, " Uninteresting event ignored\n");
				continue;
			}
			if (ignore) {
				--ignore;
				dprintf(D_L1, " Event ignored\n");
				continue;
			}
			dprintf(D_L0, "Event observed: Retry to get lock %s\n", path);
			lock = ctldir_reserve_lock(xs, path);
			if (lock < 0)
				goto err_unwatch;
		}

		if (lock)
			ret = 1;
		dprintf(D_L1, "Unwatch %s\n", path);
		xs_unwatch(xs, path, XSLOCKTOKEN); /* ignore failures */
	}
	return ret;

 err_unwatch:
	dprintf(D_L1, "Unwatch %s\n", path);
	xs_unwatch(xs, path, XSLOCKTOKEN); /* ignore failures */
 err_out:
	return -1;
}

static inline int ctldir_unlock(struct xs_handle *xs, unsigned int domid, const char *scope)
{
	xs_transaction_t xts;
	char path[256];
	int ret;

 retry:
	dprintf(D_L1, "Initialize transaction\n");
	xts = xs_transaction_start(xs);
	if (!xts) {
		eprintf("Could not initialize a transaction");
		goto err_out;
	}

	snprintf(path, sizeof(path), "%s/%u/data/%s/lock", XSBASE, domid, scope);
	dprintf(D_L0, "Release lock %s\n", path);
	if (!xs_write(xs, xts, path, "0", 1)) {
		eprintf("Could not write to XenStore entry %s: %s\n", path, strerror(errno));
		goto err_abort_xts;
	}

	dprintf(D_L1, "Finalize transaction\n");
	if (!xs_transaction_end(xs, xts, false)) {
		if (errno != EAGAIN) {
			eprintf("Could not finalize the transaction: %s\n", strerror(errno));
			goto err_out;
		}

		dprintf(D_L0, "Restart of transaction requested\n");
		goto retry;
	}
        return ret;

 err_abort_xts:
	dprintf(D_L1, "Abort transaction\n");
        while (!xs_transaction_end(xs, xts, true) && errno == EAGAIN)
		dprintf(D_L0, "Restart of transaction requested\n");
 err_out:
        return -1;
}

static inline int ctldir_has_trigger(struct xs_handle *xs, unsigned int domid, const char *scope, const char *trigger)
{
	char path[256];
	unsigned int len;
	int ival;
	char *reply;

	snprintf(path, sizeof(path), "%s/%u/data/%s/feature-%s", XSBASE, domid, scope, trigger);
	dprintf(D_L1, "Check %s\n", path);
	reply = (char *) xs_read(xs, XBT_NULL, path, &len);
	if (!reply || len == 0) {
		eprintf("Could not read XenStore entry %s: %s\n", path, strerror(errno));
	        goto err_out;
        }
	if (sscanf(reply, "%d", &ival) != 1 || ival != 1) {
		eprintf("Could not parse XenStore entry %s\n", path);
	        goto err_free_reply;
        }
	free(reply);

	dprintf(D_L0, "Trigger %s is available\n", trigger);
	return 0;

 err_free_reply:
	free(reply);
 err_out:
	eprintf("Trigger %s is not available or unsupported\n", trigger);
	return -EINVAL;
}

static inline char *ctldir_trigger(struct xs_handle *xs, unsigned int domid, const char *scope, const char *trigger, const char *args)
{
	const char *iargs = "";
	char ipath[256];
	char opath[256];
	unsigned int len;
	int cmp0, cmp1;
	char *reply;
	char **vec;
	unsigned int veclen;
	unsigned int ignore = 1;
	xs_transaction_t xts;

	snprintf(ipath, sizeof(ipath), "%s/%u/data/%s/%s-in", XSBASE, domid, scope, trigger);
	snprintf(opath, sizeof(opath), "%s/%u/data/%s/%s-out", XSBASE, domid, scope, trigger);
	if (args) /* whenever no args are passed, "" is writen to XenStore */
		iargs = args;

	dprintf(D_L1, "Watch %s\n", opath);
	if (!xs_watch(xs, opath, XSTRIGGERTOKEN)) {
		eprintf("Could not setup watch on %s\n", opath);
		goto err_out;
	}

	/* send message */
 retry_write:
	dprintf(D_L1, "Initialize transaction for writing\n");
	xts = xs_transaction_start(xs);
	if (!xts) {
		eprintf("Could not initialize transaction for writing");
		goto err_unwatch;
	}
	dprintf(D_L0, "Write '%s' to %s\n", iargs, ipath);
	if (!xs_write(xs, xts, ipath, iargs, strlen(iargs))) {
		eprintf("Could not write to XenStore entry %s: %s\n", ipath, strerror(errno));
		goto err_abort_xts;
	}
	errno = 0;
	if (!xs_transaction_end(xs, xts, false)) {
		if (errno != EAGAIN) {
			eprintf("Could not finalize the transaction: %s\n", strerror(errno));
			goto err_unwatch;
		}
		dprintf(D_L0, "Restart of write transaction requested\n");
		goto retry_write;
	}

	/* wait for reply */
	dprintf(D_L0, "Wait for reply\n");
	for (;;) {
		dprintf(D_L1, "Wait for XenStore event on %s\n", opath);
		vec = xs_read_watch(xs, &veclen);
		if (!vec) {
			if (errno == EAGAIN || errno == EINTR) {
				dprintf(D_L1, "Signal ignored\n");
				continue;
			}

			eprintf("Error while watching %s: %s\n", opath, strerror(errno));
			goto err_unwatch;
		}
		dprintf(D_L1, " Event arrived: %s | %s\n",
			vec[XS_WATCH_PATH], vec[XS_WATCH_TOKEN]);
		cmp0 = strcmp(vec[XS_WATCH_TOKEN], XSTRIGGERTOKEN);
		cmp1 = strcmp(vec[XS_WATCH_PATH], opath);
		free(vec);
		if (cmp0 != 0 || cmp1 != 0) {
			/* some other event arrived */
			dprintf(D_L1, " Uninteresting event ignored\n");
			continue;
		}
		if (ignore) {
			dprintf(D_L1, " Event ingored\n");
			ignore--;
			continue;
		}
		break; /* reply received */
	}
	dprintf(D_L1, "Reply received\n");

	/* read reply */
 retry_read:
	dprintf(D_L1, "Initialize transaction for reading reply\n");
	xts = xs_transaction_start(xs);
	if (!xts) {
		eprintf("Could not initialize a transaction");
		goto err_unwatch;
	}
	dprintf(D_L1, "Read %s\n", opath);
	reply = (char *) xs_read(xs, XBT_NULL, opath, &len);
	dprintf(D_L1, "Finalize transaction\n");
	if (!xs_transaction_end(xs, xts, false)) {
		if (errno != EAGAIN) {
			eprintf("Could not finalize the transaction: %s\n", strerror(errno));
			goto err_unwatch;
		}
		dprintf(D_L0, "Restart of read transaction requested\n");
		goto retry_read;
	}
	if (!reply) {
		eprintf("Could not read XenStore entry %s: %s\n", opath, strerror(errno));
	        goto err_unwatch;
        }

	dprintf(D_L1, "Unwatch %s\n", opath);
	xs_unwatch(xs, opath, XSTRIGGERTOKEN); /* ignore failures */
	return reply;

 err_abort_xts:
	dprintf(D_L1, "Abort transaction\n");
        while (!xs_transaction_end(xs, xts, true) && errno == EAGAIN)
		dprintf(D_L0, "Restart of transaction requested\n");
 err_unwatch:
	dprintf(D_L1, "Unwatch %s\n", opath);
	xs_unwatch(xs, opath, XSTRIGGERTOKEN); /* ignore failures */
 err_out:
	return NULL;
}

int main(int argc, char **argv)
{
	struct xs_handle *xs_com;
	struct args args;
	char *reply;
	int ret;

	signal(SIGINT,  sigint_handler);
	signal(SIGTERM, sigint_handler);
	signal(SIGQUIT, sigint_handler);

	/*
	 * ARGUMENT PARSING
	 */
	memset(&args, 0, sizeof(args));
	if (parse_args(argc, argv, &args) < 0)
		goto err_out;
	if (verbosity > 0)
		eprintf("Verbosity increased to level %d.\n", verbosity);

	/*
	 * MAIN
	 */
	if (cancel)
		goto err_out;

	/* establish connection to xenstore */
	dprintf(D_L1, "Connect to XenStore daemon\n");
	xs_com = xs_open(0);
	if (!xs_com)
		dief("Could not establish connection to XenStore daemon\n");
	if (cancel)
		goto err_close_xs;

	/* check if trigger is available */
	ret = ctldir_has_trigger(xs_com, args.domid, args.scope, args.trigger);
	if (ret < 0)
		goto err_unlock;

	/* try to get lock */
	ret = ctldir_lock(xs_com, args.domid, args.scope, args.nowait);
	if (ret < 0) { /* error happened */
		dief("Failed to request lock\n");
	} else if (ret == 0) { /* lock is held already */
		dief("Interface is busy\n");
	}
	if (cancel)
		goto err_unlock;

	/* -------------------------------------------------------------- */
	/* trigger and wait for its reply (can not be canceled) */
	reply = ctldir_trigger(xs_com, args.domid, args.scope, args.trigger, args.args);
	if (!reply)
		goto err_unlock;

	printf("%s\n", reply);
	/* -------------------------------------------------------------- */

	/* unlock ctldir */
	ret = ctldir_unlock(xs_com, args.domid, args.scope);
	if (!ret)
		dief("Could not unlock \n");

	xs_close(xs_com);
	release_args(&args);
	exit(EXIT_SUCCESS);

 err_unlock:
	ctldir_unlock(xs_com, args.domid, args.scope); /* ignore errors */
 err_close_xs:
	xs_close(xs_com);
 err_out:
	exit(EXIT_FAILURE);
}
