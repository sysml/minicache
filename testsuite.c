/*
 * Copyright(C) 2013-2014 NEC Laboratories Europe. All rights reserved.
 *                        Simon Kuenzer <simon.kuenzer@neclab.eu>
 */
#include <target/sys.h>
#include <stdio.h>
#include <lwip/udp.h>

#include "shfs.h"
#include "shfs_btable.h"
#include "shfs_tools.h"
#include "shfs_cache.h"
#include "shfs_fio.h"
#include "shell.h"
#ifdef HAVE_CTLDIR
#include <target/ctldir.h>
#endif

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

static int shcmd_netdf(FILE *cio, int argc, char *argv[])
{
	SHFS_FD f;
	uint64_t fsize, left, cur, dlen;
	struct udp_pcb *upcb;
	struct pbuf *pb;
	int ret = 0;
	err_t err;
	uint64_t pkts = 0;
	struct timeval tm_start;
	struct timeval tm_end;
	uint64_t usecs, pps, bps;

	ip4_addr_t remote_ip;
	u16_t remote_port = 10692;

	unsigned int schedbatch;

	if (argc <= 1) {
		fprintf(cio, "Usage: %s [file] [[IP]]\n", argv[0]);
		ret = -1;
		goto out;
	}
	if (argc >= 3) {
		if (parse_ipv4(&remote_ip, argv[2]) < 0) {
			fprintf(cio, "Invalid target IP address specified\n");
			ret = -1;
			goto out;
		}
	} else {
		IP4_ADDR(&remote_ip, 0, 0, 0, 0);
	}

	f = shfs_fio_open(argv[1]);
	if (!f) {
		fprintf(cio, "Could not open %s: %s\n", argv[1], strerror(errno));
		ret = -1;
		goto out;
	}
	shfs_fio_size(f, &fsize);

	upcb = udp_new();
	if (!upcb) {
		fprintf(cio, "Could not allocate UDP PCB\n");
		ret = -1;
		goto close_f;
	}

	err = udp_connect(upcb, &remote_ip, remote_port);
	if (err != ERR_OK) {
		fprintf(cio, "Could bind UDP PCB to remote IP and port\n");
		ret = -1;
		goto free_upcb;
	}

	gettimeofday(&tm_start, NULL);
	left = fsize;
	cur = 0;
	schedbatch = 32;
	while (left) {
		dlen = min(left, TCP_MSS);

		pb = pbuf_alloc(PBUF_TRANSPORT, TCP_MSS, PBUF_POOL);
		if (unlikely(!pb)) {
			fprintf(cio, "Could not allocate pbuf\n");
			ret = -1;
			break;
		}
		ret = shfs_fio_cache_read(f, cur, pb->payload, dlen);
		if (unlikely(ret < 0)) {
			fprintf(cio, "%s: Read error: %s\n", argv[1], strerror(-ret));
			pbuf_free(pb);
			ret = -1;
			break;
		}
		pb->len = pb->tot_len = (u16_t) dlen;

		err = udp_send(upcb, pb);
		if (unlikely(err != ERR_OK)) {
			fprintf(cio, "%s: UDP send error: %d\n", argv[1], err);
			pbuf_free(pb);
			ret = -1;
			break;
		}

		pkts++;
		left -= dlen;
		cur += dlen;
		pbuf_free(pb);

		--schedbatch;
		if (!schedbatch) {
			schedbatch = 32;
			schedule();
		}
	}

	if (pkts) {
		gettimeofday(&tm_end, NULL);
		if (tm_end.tv_usec < tm_start.tv_usec) {
			tm_end.tv_usec += 1000000l;
			--tm_end.tv_sec;
		}
		usecs = (tm_end.tv_usec - tm_start.tv_usec);
		usecs += (tm_end.tv_sec - tm_start.tv_sec) * 1000000;
		pps = (pkts * 1000000 + usecs / 2) / usecs; /* from pkt-gen */
		bps = (cur * 1000000 + usecs / 2) / usecs;
		fprintf(cio, "%s: Sent %lu bytes payload in %lu packets in %lu.%06u seconds to the stack (%lu pps, ",
		        argv[1], cur, pkts, usecs / 1000000, usecs % 1000000, pps);
		if (bps > 1000000000) {
			bps /= 10000000;
			fprintf(cio, "%lu.%02lu GB/s)\n", bps / 100, bps % 100);
		} else if (bps > 1000000) {
			bps /= 10000;
			fprintf(cio, "%lu.%02lu MB/s)\n", bps / 100, bps % 100);
		} else if (bps > 1000) {
			bps /= 10;
			fprintf(cio, "%lu.%02lu KB/s)\n", bps / 100, bps % 100);
		} else {
			fprintf(cio, "%lu B/s)\n", bps);
		}
	}

 free_upcb:
	schedule();
	udp_remove(upcb);
 close_f:
	shfs_fio_close(f);
 out:
	return ret;
}

/* sequential read performance */
static int shcmd_ioperf(FILE *cio, int argc, char *argv[])
{
	SHFS_FD f;
	uint64_t fsize, left, cur, dlen;
	int ret = 0;
	struct timeval tm_start;
	struct timeval tm_end;
	unsigned int t;
	unsigned int times = 1;
	uint64_t usecs, bps;
	void *buf;
	size_t buflen = 0;

	if (argc <= 1) {
		fprintf(cio, "Usage: %s [file] [[times]] [[buffer length]]\n", argv[0]);
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
			fprintf(stderr, "Could not parse buffer length\n");
			ret = -1;
			goto out;
		}
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
		goto out;
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

	gettimeofday(&tm_start, NULL);
	barrier();
	for (t = 0; t < times; ++t) {
		left = fsize;
		cur = 0;

		while (left) {
			dlen = min(left, buflen);

			ret = shfs_fio_cache_read(f, cur, buf, dlen);
			if (unlikely(ret < 0)) {
				fprintf(cio, "%s: Read error: %s\n", argv[1], strerror(-ret));
				ret = -1;
				goto out_close_f;
			}

			left -= dlen;
			cur += dlen;
		}
	}
	barrier();
	gettimeofday(&tm_end, NULL);

	if (ret >= 0 && times > 0) {
		if (tm_end.tv_usec < tm_start.tv_usec) {
			tm_end.tv_usec += 1000000l;
			--tm_end.tv_sec;
		}
		usecs = (tm_end.tv_usec - tm_start.tv_usec);
		usecs += (tm_end.tv_sec - tm_start.tv_sec) * 1000000;
		fprintf(cio, "%s: Read %lu bytes in %"PRIu64".%06"PRIu64" seconds ",
		        argv[1], fsize * times, usecs / 1000000, usecs % 1000000);
		bps = (fsize * times * 1000000 + usecs / 2) / usecs;
		if (bps > 1000000000) {
			bps /= 10000000;
			fprintf(cio, "(%"PRIu64".%02"PRIu64" GB/s)\n", bps / 100, bps % 100);
		} else if (bps > 1000000) {
			bps /= 10000;
			fprintf(cio, "(%"PRIu64".%02"PRIu64" MB/s)\n", bps / 100, bps % 100);
		} else if (bps > 1000) {
			bps /= 10;
			fprintf(cio, "(%"PRIu64".%02"PRIu64" KB/s)\n", bps / 100, bps % 100);
		} else {
			fprintf(cio, "(%"PRIu64" B/s)\n", bps);
		}
	}

	target_free(buf);
 out_close_f:
	shfs_fio_close(f);
 out:
	return ret;
}

/* sequential I/O performance */
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
		ctldir_register_shcmd(cd, "ocperf", shcmd_ocperf);
	}
#endif

#ifdef HAVE_SHELL
	/* shell commands (ignore errors) */
	shell_register_cmd("blast", shcmd_blast);
	shell_register_cmd("netdf", shcmd_netdf);
	shell_register_cmd("ioperf", shcmd_ioperf);
	shell_register_cmd("ocperf", shcmd_ocperf);
#endif

	return 0;
}
