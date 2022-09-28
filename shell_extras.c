/*
 * MicroShell (µSh)
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
 */

#include <target/sys.h>
#include <errno.h>
#include <sched.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include "likely.h"

#ifdef SHELL_DEBUG
#define ENABLE_DEBUG
#endif
#include "debug.h"

#include "shell_extras.h"

#ifdef __MINIOS__
static int shcmd_free(FILE *cio, int argc, char *argv[]);
#endif
#if defined HAVE_LIBC && !defined CONFIG_ARM
static int shcmd_mallinfo(FILE *cio, int argc, char *argv[]);
#endif
#ifdef HAVE_LWIP
static int shcmd_ifconfig(FILE *cio, int argc, char *argv[]);
#if LWIP_STATS_DISPLAY
static int shcmd_lwipstats(FILE *cio, int argc, char *argv[]);
#endif
#endif

#ifdef HAVE_CTLDIR
int register_shell_extras(struct ctldir *cd)
{
	/* ctldir entries (ignore errors) */
	if (cd) {
#ifdef __MINIOS__
		ctldir_register_shcmd(cd, "free",   shcmd_free);
#endif
#if defined HAVE_LIBC && !(defined __MINIOS__ && defined CONFIG_ARM)
		ctldir_register_shcmd(cd, "mallinfo",shcmd_mallinfo);
#endif
#ifdef HAVE_LWIP
		ctldir_register_shcmd(cd, "ifconfig",shcmd_ifconfig);
#if LWIP_STATS_DISPLAY
		ctldir_register_shcmd(cd, "lwip-stats",shcmd_lwipstats);
#endif
#endif
	}
#else
int register_shell_extras(void)
{
#endif
#ifdef __MINIOS__
    shell_register_cmd("free",   shcmd_free);
#endif
#if defined HAVE_LIBC && !(defined __MINIOS__ && defined CONFIG_ARM)
    shell_register_cmd("mallinfo",shcmd_mallinfo);
#endif
#ifdef HAVE_LWIP
    shell_register_cmd("ifconfig",shcmd_ifconfig);
#if LWIP_STATS_DISPLAY
    shell_register_cmd("lwip-stats",shcmd_lwipstats);
#endif
#endif

    return 0;
}

#if defined __MINIOS__
#include <mini-os/mm.h>

static int shcmd_free(FILE *cio, int argc, char *argv[])
{
    uint64_t base;
    char mode = 'm';

    /* parsing */
    base = 1;
    if (argc == 2) {
	    if (strcmp(argv[1], "-k") == 0)
		    base = 1024;
	    else if (strcmp(argv[1], "-m") == 0)
		    base = 1024 * 1024;
	    else if (strcmp(argv[1], "-g") == 0)
		    base = 1024 * 1024 * 1024;
	    else if (strcmp(argv[1], "-p") == 0)
		    mode = 'p';
	    else if (strcmp(argv[1], "-u") == 0)
		    mode = 'u';
	    else
		    goto usage;
    } else if (argc > 2) {
	    goto usage;
    }

    /* output */
    switch (mode) {
    case 'u': /* base units */
        fprintf(cio, "Page size: %5lu KiB\nStack size: %4lu KiB\n",
                PAGE_SIZE / 1024,
                STACK_SIZE / 1024);
        break;

    case 'p': /* pages */
        do {
	    uint64_t total_p     = arch_mem_size() >> PAGE_SHIFT;
	    uint64_t free_p      = mm_free_pages();
	    uint64_t reserved_p  = arch_reserved_mem() >> PAGE_SHIFT;
	    uint64_t allocated_p = mm_total_pages() - free_p;
#if defined HAVE_LIBC && !defined CONFIG_ARM
	    uint64_t heap_p      = mm_heap_pages();
	    allocated_p       -= heap_p; /* excludes heap pages from page allocator */
#endif

	    fprintf(cio, "       ");
	    fprintf(cio, "%12s ", "total");
	    fprintf(cio, "%12s ", "reserved");
	    fprintf(cio, "%12s ", "allocated");
#if defined HAVE_LIBC && !defined CONFIG_ARM
	    fprintf(cio, "%12s ", "heap");
#endif
	    fprintf(cio, "%12s\n", "free");

	    fprintf(cio, "Pages: ");
	    fprintf(cio, "%12"PRIu64" ", total_p);
	    fprintf(cio, "%12"PRIu64" ", reserved_p);
	    fprintf(cio, "%12"PRIu64" ", allocated_p);
#if defined HAVE_LIBC && !defined CONFIG_ARM
	    fprintf(cio, "%12"PRIu64" ", heap_p);
#endif
	    fprintf(cio, "%12"PRIu64"\n", free_p);
        } while(0);
        break;
    default: /* mem */
        do {
	    uint64_t total_s     = arch_mem_size();
	    uint64_t free_s      = mm_free_pages() << PAGE_SHIFT;
	    uint64_t other_s     = arch_reserved_mem();
	    uint64_t text_s      = ((uint64_t) &_erodata - (uint64_t) &_text);  /* text and read only data sections */
	    uint64_t data_s      = ((uint64_t) &_edata - (uint64_t) &_erodata); /* rw data section */
	    uint64_t bss_s       = ((uint64_t) &_end - (uint64_t) &_edata); /* bss section */
	    uint64_t allocated_s = (mm_total_pages() - mm_free_pages()) << PAGE_SHIFT;
#if defined HAVE_LIBC && !defined CONFIG_ARM
	    uint64_t heap_s      = mm_heap_pages() << PAGE_SHIFT;
	    allocated_s       -= heap_s; /* excludes heap pages from page allocator */
#endif
	    other_s -= text_s + data_s + bss_s;

	    fprintf(cio, "       ");
	    fprintf(cio, "%12s ", "total");
	    fprintf(cio, "%12s ", "text");
	    fprintf(cio, "%12s ", "data");
	    fprintf(cio, "%12s ", "bss");
	    fprintf(cio, "%12s ", "other");
	    fprintf(cio, "%12s ", "allocated");
#if defined HAVE_LIBC && !defined CONFIG_ARM
	    fprintf(cio, "%12s ", "heap");
#endif
	    fprintf(cio, "%12s\n", "free");

	    fprintf(cio, "Mem:   ");
	    fprintf(cio, "%12"PRIu64" ", total_s / base);
	    fprintf(cio, "%12"PRIu64" ", text_s / base);
	    fprintf(cio, "%12"PRIu64" ", data_s / base);
	    fprintf(cio, "%12"PRIu64" ", bss_s / base);
	    fprintf(cio, "%12"PRIu64" ", other_s / base);
	    fprintf(cio, "%12"PRIu64" ", allocated_s / base);
#if defined HAVE_LIBC && !defined CONFIG_ARM
	    fprintf(cio, "%12"PRIu64" ", heap_s / base);
#endif
	    fprintf(cio, "%12"PRIu64"\n", free_s /base);
        } while(0);
        break;
    }
    return 0;

 usage:
    fprintf(cio, "%s [[-k|-m|-g|-p|-u]]\n", argv[0]);
    return -1;
}
#endif

#if defined HAVE_LIBC && !defined CONFIG_ARM
static int shcmd_mallinfo(FILE *cio, int argc, char *argv[])
{
    struct mallinfo minfo;
    minfo = mallinfo();

    fprintf(cio, " Total space allocated from system:        %12lu B\n", minfo.arena);
    fprintf(cio, " Number of non-inuse chunks:               %12lu\n", minfo.ordblks);
    fprintf(cio, " Number of mmapped regions:                %12lu\n", minfo.hblks);
    fprintf(cio, " Total space in mmapped regions:           %12lu B\n", minfo.hblkhd);
    fprintf(cio, " Total allocated space:                    %12lu B\n", minfo.uordblks);
    fprintf(cio, " Total non-inuse space:                    %12lu B\n", minfo.fordblks);
    fprintf(cio, " Top-most, releasable space (malloc_trim): %12lu B\n", minfo.keepcost);
    fprintf(cio, " Average size of non-inuse chunks:         %12lu B\n", minfo.fordblks / minfo.ordblks);

    return 0;
}
#endif

#ifdef HAVE_LWIP
#include <lwip/tcp.h>

static int shcmd_ifconfig(FILE *cio, int argc, char *argv[])
{
	/* prints available interfaces */
	struct netif *netif;
	int is_up;
	uint8_t flags;

	for (netif = netif_list; netif != NULL; netif = netif->next) {
		is_up = netif_is_up(netif);
		flags = netif->flags;

		/* name + mac */
		fprintf(cio, "%c%c %c      ",
		        (netif->name[0] ? netif->name[0] : ' '),
		        (netif->name[1] ? netif->name[1] : ' '),
		        (netif == netif_default ? '*' : ' '));
		fprintf(cio, "HWaddr %02x:%02x:%02x:%02x:%02x:%02x\n",
		        netif->hwaddr[0], netif->hwaddr[1],
		        netif->hwaddr[2], netif->hwaddr[3],
		        netif->hwaddr[4], netif->hwaddr[5]);
		/* flags + mtu */
		fprintf(cio, "          ");
		if (flags & NETIF_FLAG_UP)
			fprintf(cio, "UP ");
		if (flags & NETIF_FLAG_BROADCAST)
			fprintf(cio, "BROADCAST ");
		if (flags & NETIF_FLAG_ETHARP)
			fprintf(cio, "ARP ");
		if (flags & NETIF_FLAG_ETHERNET)
			fprintf(cio, "ETHERNET ");
#ifdef CONFIG_NETFRONT_GSO
		fprintf(cio, "GSO ");
#endif
#if LWIP_CHECKSUM_PARTIAL
		fprintf(cio, "CSO ");
#endif
#ifdef  CONFIG_NETFRONT_PERSISTENT_GRANTS
		fprintf(cio, "PGNTS ");
#endif
#ifdef CONFIG_LWIP_BATCHTX
		fprintf(cio, "BTH ");
#endif
#ifdef CONFIG_LWIP_WAITFORTX
		fprintf(cio, "WTX ");
#endif
		if (netif->dhcp)
			fprintf(cio, "DHCP ");
		fprintf(cio, "MTU:%u\n", netif->mtu);
	        /* ip addr */
		if (is_up) {
			fprintf(cio, "          inet addr:%u.%u.%u.%u",
			        ip4_addr1(&netif->ip_addr),
			        ip4_addr2(&netif->ip_addr),
			        ip4_addr3(&netif->ip_addr),
			        ip4_addr4(&netif->ip_addr));
			fprintf(cio, " Mask:%u.%u.%u.%u",
			        ip4_addr1(&netif->netmask),
			        ip4_addr2(&netif->netmask),
			        ip4_addr3(&netif->netmask),
			        ip4_addr4(&netif->netmask));
			fprintf(cio, " Gw:%u.%u.%u.%u\n",
			        ip4_addr1(&netif->gw),
			        ip4_addr2(&netif->gw),
			        ip4_addr3(&netif->gw),
			        ip4_addr4(&netif->gw));
		}
	}
	return 0;
}

#if LWIP_STATS_DISPLAY
#include <lwip/stats.h>

int shcmd_lwipstats(FILE *cio, int argc, char *argv[])
{
	stats_display();
	fprintf(cio, "lwIP stats dumped to system output\n");
	return 0;
}
#endif
#endif
