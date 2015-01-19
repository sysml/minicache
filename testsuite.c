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

static inline int parse_ipv4(struct ip_addr *out, const char *buf)
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

	struct ip_addr remote_ip;
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

static int shcmd_ioperf(FILE *cio, int argc, char *argv[])
{
	SHFS_FD f;
	uint64_t fsize, left, cur, dlen;
	int ret = 0;
	struct timeval tm_start;
	struct timeval tm_end;
	uint64_t usecs, bps;
	void *buf;
	size_t buflen;

	if (argc <= 1) {
		fprintf(cio, "Usage: %s [file]\n", argv[0]);
		ret = -1;
		goto out;
	}

	f = shfs_fio_open(argv[1]);
	if (!f) {
		fprintf(cio, "Could not open %s: %s\n", argv[1], strerror(errno));
		ret = -1;
		goto out;
	}
	shfs_fio_size(f, &fsize);

	buflen = shfs_vol.chunksize;
	buf = _xmalloc(shfs_vol.chunksize, 8);
	if (!buf) {
		fprintf(cio, "Out of memory\n");
		ret = -1;
		goto out_close_f;
	}

	left = fsize;
	cur = 0;
	gettimeofday(&tm_start, NULL);
	while (left) {
		dlen = min(left, buflen);

		ret = shfs_fio_cache_read(f, cur, buf, dlen);
		if (unlikely(ret < 0)) {
			fprintf(cio, "%s: Read error: %s\n", argv[1], strerror(-ret));
			ret = -1;
			break;
		}

		left -= dlen;
		cur += dlen;
	}
	gettimeofday(&tm_end, NULL);

	if (ret >= 0) {
		if (tm_end.tv_usec < tm_start.tv_usec) {
			tm_end.tv_usec += 1000000l;
			--tm_end.tv_sec;
		}
		usecs = (tm_end.tv_usec - tm_start.tv_usec);
		usecs += (tm_end.tv_sec - tm_start.tv_sec) * 1000000;
		fprintf(cio, "%s: Read %lu bytes in %lu.%06u seconds ",
		        argv[1], cur, usecs / 1000000, usecs % 1000000);
		bps = (cur * 1000000 + usecs / 2) / usecs;
		if (bps > 1000000000) {
			bps /= 10000000;
			fprintf(cio, "(%lu.%02lu GB/s)\n", bps / 100, bps % 100);
		} else if (bps > 1000000) {
			bps /= 10000;
			fprintf(cio, "(%lu.%02lu MB/s)\n", bps / 100, bps % 100);
		} else if (bps > 1000) {
			bps /= 10;
			fprintf(cio, "(%lu.%02lu KB/s)\n", bps / 100, bps % 100);
		} else {
			fprintf(cio, "(%lu B/s)\n", bps);
		}
	}
 out_close_f:
	shfs_fio_close(f);
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
		ctldir_register_shcmd(cd, "netdf", shcmd_netdf);
	}
#endif

	/* shell commands (ignore errors) */
	shell_register_cmd("netdf", shcmd_netdf);
	shell_register_cmd("ioperf", shcmd_ioperf);

	return 0;
}
