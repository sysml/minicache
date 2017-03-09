/*
 * MiniCache Test Suite for MicroShell
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

#include <target/sys.h>
#include <stdio.h>
#include <lwip/udp.h>
#include <sys/time.h>

#include "shfs.h"
#include "shfs_btable.h"
#include "shfs_tools.h"
#include "shfs_cache.h"
#include "shfs_fio.h"
#include "shell.h"
#ifdef HAVE_CTLDIR
#include <target/ctldir.h>
#endif

/* copied from <sys/time.h> */
#ifndef timerclear
#define timerclear(tvp)         ((tvp)->tv_sec = (tvp)->tv_usec = 0)
#endif

#ifndef timeradd
#define timeradd(a, b, result)                                                \
  do {                                                                        \
    (result)->tv_sec = (a)->tv_sec + (b)->tv_sec;                             \
    (result)->tv_usec = (a)->tv_usec + (b)->tv_usec;                          \
    if ((result)->tv_usec >= 1000000)                                         \
      {                                                                       \
        ++(result)->tv_sec;                                                   \
        (result)->tv_usec -= 1000000;                                         \
      }                                                                       \
  } while (0)
#endif

#ifndef timersub
#define timersub(a, b, result)                                                \
  do {                                                                        \
    (result)->tv_sec = (a)->tv_sec - (b)->tv_sec;                             \
    (result)->tv_usec = (a)->tv_usec - (b)->tv_usec;                          \
    if ((result)->tv_usec < 0) {                                              \
      --(result)->tv_sec;                                                     \
      (result)->tv_usec += 1000000;                                           \
    }                                                                         \
  } while (0)
#endif
/* --- */

static inline int parse_ipv4(ip4_addr_t *out, const char *buf)
{
	int ip0, ip1, ip2, ip3;

	if (sscanf(buf, "%d.%d.%d.%d", &ip0, &ip1, &ip2, &ip3) != 4)
		return -1;
	if ((ip0 < 0 || ip0 > 255) ||
	    (ip1 < 0 || ip1 > 255) ||
	    (ip2 < 0 || ip2 > 255) ||
	    (ip3 < 0 || ip3 > 255))
		return -1;

	IP4_ADDR(out, ip0, ip1, ip2, ip3);
	return 0;
}

static int shcmd_blast(FILE *cio, int argc, char *argv[])
{
	// *((uint16_t *)0) = 0xD1E;
	target_crash(); /* never returns */
	fprintf(cio, "Failed to crash this instance\n");
	return -1;
}

/* sequential read performance */
static int shcmd_ioperf(FILE *cio, int argc, char *argv[])
{
	SHFS_FD f;
	uint64_t fsize, left, cur, dlen;
	int ret = 0;
	int flush = 0;
	struct timeval tm_start;
	struct timeval tm_end;
	struct timeval tm_diff;
	struct timeval tm_duration;
	unsigned int t;
	unsigned int times = 1;
	uint64_t usecs, bps, reqs;
	void *buf;
	size_t buflen = 0;

	if (argc <= 1) {
		fprintf(cio, "Usage: %s [file] [[times]] [[buffer length]] [[flush]]\n", argv[0]);
		ret = -1;
		goto out;
	}
	if (argc >= 3) {
		if ((sscanf(argv[2], "%u", &times)) != 1) {
			fprintf(cio, "Could not parse times\n");
			ret = -1;
			goto out;
		}
	}
	if (argc >= 4) {
		if ((sscanf(argv[3], "%"SCNu64"", &buflen)) != 1 || buflen == 0) {
			fprintf(cio, "Could not parse buffer length\n");
			ret = -1;
			goto out;
		}
	}
	if (argc >= 5) {
		if (strcmp(argv[4], "flush") == 0)
			flush = 1;
	}

	f = shfs_fio_open(argv[1]);
	if (!f) {
		fprintf(cio, "Could not open %s: %s\n", argv[1], strerror(errno));
		ret = -1;
		goto out;
	}
	if (shfs_fio_islink(f)) {
		fprintf(cio, "File %s is a link\n", argv[1]);
		ret = -1;
		goto out_close_f;
	}
	shfs_fio_size(f, &fsize);

	if (buflen == 0)
		buflen = shfs_vol.chunksize;
	buflen = min(fsize, buflen);
	buf = target_malloc(8, buflen);
	if (!buf) {
		fprintf(cio, "Out of memory\n");
		ret = -1;
		goto out_close_f;
	}
	fprintf(cio, "%s: file size: %"PRIu64" B, read buffer length: %"PRIu64" B, read %d times\n",
	       argv[1], fsize, buflen, times);

	reqs = 0;
	if (!flush) {
		gettimeofday(&tm_start, NULL);
		barrier();
		for (t = 0; t < times; ++t) {
			left = fsize;
			cur = 0;

			while (left) {
				dlen = min(left, buflen);

				ret = shfs_fio_cache_read_nosched(f, cur, buf, dlen);
				if (unlikely(ret < 0)) {
					fprintf(cio, "%s: Read error: %s\n", argv[1], strerror(-ret));
					ret = -1;
					goto out_close_f;
				}

				++reqs;
				left -= dlen;
				cur += dlen;
			}
		}
		barrier();
		gettimeofday(&tm_end, NULL);
		timersub(&tm_end, &tm_start, &tm_duration);
	} else {
		fprintf(cio, "%s: Flushing SHFS cache before each iteration\n", argv[1]);
		timerclear(&tm_duration);
		for (t = 0; t < times; ++t) {
			shfs_flush_cache();
			barrier();
			gettimeofday(&tm_start, NULL);
			barrier();
			left = fsize;
			cur = 0;

			while (left) {
				dlen = min(left, buflen);

				ret = shfs_fio_cache_read_nosched(f, cur, buf, dlen);
				if (unlikely(ret < 0)) {
					fprintf(cio, "%s: Read error: %s\n", argv[1], strerror(-ret));
					ret = -1;
					goto out_close_f;
				}

				++reqs;
				left -= dlen;
				cur += dlen;
			}
			barrier();
			gettimeofday(&tm_end, NULL);
			timersub(&tm_end, &tm_start, &tm_diff);
			timeradd(&tm_diff, &tm_duration, &tm_duration);
		}
	}

	if (ret >= 0 && times > 0) {
		usecs = (tm_duration.tv_usec);
		usecs += (tm_duration.tv_sec) * 1000000;
		fprintf(cio, "%s: Read %lu bytes with %"PRIu64" requests in %"PRIu64".%06"PRIu64" seconds ",
		        argv[1], fsize * times, reqs, usecs / 1000000, usecs % 1000000);
		bps = (fsize * times * 1000000 + usecs / 2) / usecs;
		reqs = (reqs * 1000000 + usecs / 2) / usecs;
		fprintf(cio, "(%"PRIu64" B/s, %"PRIu64" req/s)\n", bps, reqs);
	}

	target_free(buf);
 out_close_f:
	shfs_fio_close(f);
 out:
	return ret;
}

/* sequential read performance without doing a memcpy to a target buffer */
static int shcmd_ioperf2(FILE *cio, int argc, char *argv[])
{
	SHFS_FD f;
	chk_t fsize, c, start, end;
	struct shfs_cache_entry *cce;
	int ret = 0;
	int flush = 0;
	struct timeval tm_start;
	struct timeval tm_end;
	struct timeval tm_diff;
	struct timeval tm_duration;
	unsigned int t;
	unsigned int times = 1;
	uint64_t usecs, bps, reqs;

	if (argc <= 1) {
		fprintf(cio, "Usage: %s [file] [[times]] [[flush]]\n", argv[0]);
		ret = -1;
		goto out;
	}
	if (argc >= 3) {
		if ((sscanf(argv[2], "%u", &times)) != 1) {
			fprintf(cio, "Could not parse times\n");
			ret = -1;
			goto out;
		}
	}
	if (argc >= 4) {
		if (strcmp(argv[3], "flush") == 0)
			flush = 1;
	}

	f = shfs_fio_open(argv[1]);
	if (!f) {
		fprintf(cio, "Could not open %s: %s\n", argv[1], strerror(errno));
		ret = -1;
		goto out;
	}
	if (shfs_fio_islink(f)) {
		fprintf(cio, "File %s is a link\n", argv[1]);
		ret = -1;
		goto out_close_f;
	}
	start = shfs_volchk_foff(f, 0);
	fsize = shfs_fio_size_chks(f);
	end = start + fsize;

	fprintf(cio, "%s: file size: %"PRIu64" chunks, read length: %"PRIu32" B, read %d times\n",
	       argv[1], fsize, shfs_vol.chunksize, times);

	reqs = 0;
	if (!flush) {
		gettimeofday(&tm_start, NULL);
		barrier();
		for (t = 0; t < times; ++t) {
			for (c = start; c < end; ++c) {
				cce = shfs_cache_read_nosched(c); /* does not call schedule() */
				if (unlikely(!cce)) {
					fprintf(cio, "%s: Read error: %s\n", argv[1], strerror(-ret));
					goto out_close_f;
				}
				shfs_cache_release(cce);
				++reqs;
			}
		}
		barrier();
		gettimeofday(&tm_end, NULL);
		timersub(&tm_end, &tm_start, &tm_duration);
	} else {
		fprintf(cio, "%s: Flushing SHFS cache before each iteration\n", argv[1]);
		timerclear(&tm_duration);
		for (t = 0; t < times; ++t) {
			shfs_flush_cache();
			barrier();
			gettimeofday(&tm_start, NULL);
			barrier();
			for (c = start; c < end; ++c) {
				cce = shfs_cache_read_nosched(c); /* does not call schedule() */
				if (unlikely(!cce)) {
					fprintf(cio, "%s: Read error: %s\n", argv[1], strerror(-ret));
					goto out_close_f;
				}
				shfs_cache_release(cce);
				++reqs;
			}

			barrier();
			gettimeofday(&tm_end, NULL);
			timersub(&tm_end, &tm_start, &tm_diff);
			timeradd(&tm_diff, &tm_duration, &tm_duration);
		}
	}

	if (ret >= 0 && times > 0) {
		usecs = (tm_duration.tv_usec);
		usecs += (tm_duration.tv_sec) * 1000000;
		fprintf(cio, "%s: Read %lu bytes with %"PRIu64" requests in %"PRIu64".%06"PRIu64" seconds ",
		        argv[1], fsize * shfs_vol.chunksize * times, reqs, usecs / 1000000, usecs % 1000000);
		bps = (fsize * shfs_vol.chunksize * times * 1000000 + usecs / 2) / usecs;
		reqs = (reqs * 1000000 + usecs / 2) / usecs;
		fprintf(cio, "(%"PRIu64" B/s, %"PRIu64" req/s)\n", bps, reqs);
	}

 out_close_f:
	shfs_fio_close(f);
 out:
	return ret;
}

/* open+close performance */
static int shcmd_ocperf(FILE *cio, int argc, char *argv[])
{
	SHFS_FD f;
	const char *fname;
	uint64_t i;
	uint64_t times = 10000000;
	int ret = 0;
	struct timeval tm_start;
	struct timeval tm_end;
	uint64_t usecs, ops;

	if (argc <= 1) {
		fprintf(cio, "Usage: %s [file] [[times]]\n", argv[0]);
		ret = -1;
		goto out;
	}
	if (argc >= 3) {
		if (sscanf(argv[2], "%"SCNu64"", &times) != 1) {
			fprintf(cio, "Could not parse times\n");
			ret = -1;
			goto out;
		}
	}

	fname = argv[1];
	f = shfs_fio_open(fname);
	if (!f) {
		fprintf(cio, "Could not open %s: %s\n", fname, strerror(errno));
		ret = -1;
		goto out;
	}
	shfs_fio_close(f);

	gettimeofday(&tm_start, NULL);
	barrier();
	for (i = 0; i < times; ++i) {
		f = shfs_fio_open(fname);
		if (unlikely(!f)) {
			ret = -errno;
			break;
		}
		shfs_fio_close(f);
	}
	barrier();
	gettimeofday(&tm_end, NULL);

	if (f) {
		if (tm_end.tv_usec < tm_start.tv_usec) {
			tm_end.tv_usec += 1000000l;
			--tm_end.tv_sec;
		}
		usecs = (tm_end.tv_usec - tm_start.tv_usec);
		usecs += (tm_end.tv_sec - tm_start.tv_sec) * 1000000;
		fprintf(cio, "%s: Opened and closed %"PRIu64" times in %"PRIu64".%06"PRIu64" seconds ",
		        argv[1], times, usecs / 1000000, usecs % 1000000);
		ops = (times * 1000000 + usecs / 2) / usecs;
		fprintf(cio, "(%"PRIu64" open+close/s)\n", ops);
	}
 out:
	return ret;
}

/* open+close performance */
static int shcmd_ocperf2(FILE *cio, int argc, char *argv[])
{
	SHFS_FD f;
	hash512_t h;
	const char *str_h;
	uint64_t i;
	uint64_t times = 10000000;
	int ret = 0;
	struct timeval tm_start;
	struct timeval tm_end;
	uint64_t usecs, ops;

	if (argc <= 1) {
		fprintf(cio, "Usage: %s [hash] [[times]]\n", argv[0]);
		ret = -1;
		goto out;
	}
	if (argc >= 3) {
		if (sscanf(argv[2], "%"SCNu64"", &times) != 1) {
			fprintf(cio, "Could not parse times\n");
			ret = -1;
			goto out;
		}
	}

	str_h = argv[1];
	if ((str_h[0] == SHFS_HASH_INDICATOR_PREFIX) && (str_h[1] != '\0')) {
		if (hash_parse(str_h + 1, h, shfs_vol.hlen) < 0) {
			fprintf(cio, "Could not parse hash digest from '%s'\n", str_h);
			ret = -1;
			goto out;
		}
	} else {
		if (hash_parse(str_h, h, shfs_vol.hlen) < 0) {
			fprintf(cio, "Could not parse hash digest from '%s'\n", str_h);
			ret = -1;
			goto out;
		}
	}
	f = shfs_fio_openh(h);
	if (!f) {
		fprintf(cio, "Could not open %s: %s\n", str_h, strerror(errno));
		ret = -1;
		goto out;
	}
	shfs_fio_close(f);

	gettimeofday(&tm_start, NULL);
	barrier();
	for (i = 0; i < times; ++i) {
		f = shfs_fio_openh(h);
		if (unlikely(!f)) {
			ret = -errno;
			break;
		}
		shfs_fio_close(f);
	}
	barrier();
	gettimeofday(&tm_end, NULL);

	if (f) {
		if (tm_end.tv_usec < tm_start.tv_usec) {
			tm_end.tv_usec += 1000000l;
			--tm_end.tv_sec;
		}
		usecs = (tm_end.tv_usec - tm_start.tv_usec);
		usecs += (tm_end.tv_sec - tm_start.tv_sec) * 1000000;
		fprintf(cio, "%s: Opened and closed %"PRIu64" times in %"PRIu64".%06"PRIu64" seconds ",
		        argv[1], times, usecs / 1000000, usecs % 1000000);
		ops = (times * 1000000 + usecs / 2) / usecs;
		fprintf(cio, "(%"PRIu64" open+close/s)\n", ops);
	}
 out:
	return ret;
}

#ifdef HAVE_CTLDIR
int register_testsuite(struct ctldir *cd)
#else
int register_testsuite(void)
#endif
{
#ifdef HAVE_CTLDIR
	/* ctldir entries (ignore errors) */
	if (cd) {
		ctldir_register_shcmd(cd, "blast", shcmd_blast);
		ctldir_register_shcmd(cd, "ioperf", shcmd_ioperf);
		ctldir_register_shcmd(cd, "ioperf2", shcmd_ioperf2);
		ctldir_register_shcmd(cd, "ocperf", shcmd_ocperf);
		ctldir_register_shcmd(cd, "ocperf2", shcmd_ocperf2);
	}
#endif

#ifdef HAVE_SHELL
	/* shell commands (ignore errors) */
	shell_register_cmd("blast", shcmd_blast);
	shell_register_cmd("ioperf", shcmd_ioperf);
	shell_register_cmd("ioperf2", shcmd_ioperf2);
	shell_register_cmd("ocperf", shcmd_ocperf);
	shell_register_cmd("ocperf2", shcmd_ocperf2);
#endif

	return 0;
}
