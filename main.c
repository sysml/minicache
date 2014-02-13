#include <mini-os/os.h>
#include <mini-os/types.h>
#include <mini-os/xmalloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <getopt.h>
#include <kernel.h>
#include <pkt_copy.h>

#include "ring.h"
#include "mempool.h"
#include "pktbuf.h"
#include "nmdev.h"
#include "blkdev.h"
#include "hexdump.h"

#define RXFIFO_LEN 1024 /* can have 1023 elements */
#define TXFIFO_LEN 8192 /* can have 8191 elements */
#define MAX_RX_BURST_LEN 64
#define MAX_TX_BURST_LEN 1023 /* netmap buffer size */
#define MAX_HANDLE_BURST_LEN 16
#define PKTPOOL_SIZE 8192
#define IOBPOOL_SIZE 1024
#define PKTENCAP_HDRSIZE (sizeof(struct eth_hdr) + sizeof(struct ip_hdr) + sizeof(struct udp_hdr))
#define MAX_PKTPAYLOAD (1536 - PKTENCAP_HDRSIZE)
#define MIN_PKTIOPAYLOAD 64 /* minimum I/O load in a packet (set to 64 because of pktcopy) */
#define PKT_TTL 2
#define PRINT_STATISTICS_SEC 1 /* print statistics each ... second */

#ifndef min
#define min(a, b) \
    ({ __typeof__ (a) __a = (a); \
       __typeof__ (b) __b = (b); \
       __a < __b ? __a : __b; })
#endif
#ifndef min3
#define min3(a, b, c) (min(min((a), (b)), (c)))
#endif
#ifndef min4
#define min4(a, b ,c, d) (min(min((a), (b)), min((c), (d))))
#endif

/* checks if a number is a power of two. Copied from BNX2X driver (Linux) */
#ifndef POWER_OF_2
  #define POWER_OF_2(x)   ((0 != (x)) && (0 == ((x) & ((x)-1))))
#endif

static uint64_t statistics_nb_read_blocks = 0;
static uint64_t statistics_nb_sent_packets = 0;

struct _args {
    int ndid;
    int bdid;
    struct eth_addr src_mac;
    struct ip_addr src_ip;
    uint16_t src_port;
    struct eth_addr dst_mac;
    struct ip_addr dst_ip;
    uint16_t dst_port;
    uint8_t ttl;
    
    int pchksum; /* enable UDP payload checksumming? */
    size_t blksize; /* block size per request */
    size_t sectors_per_blk; /* disk sectors per request */
    size_t addpayload; /* additional payload for each packet (simulating protocol overhead) */
    uint32_t nb_chunks; /* number of chunk packets per request */
    size_t chunklen; /* length of an I/O chunk */
    size_t chunk_pktlen; /* pktlen of a chunk packet */
} args;

static inline void receive(struct nmdev *nm, struct ring *rxfifo)
{
    uint32_t burstlen, i;
    struct nmbuf rxbufs[MAX_RX_BURST_LEN];
    
    nmdev_notify_recv(nm);
    burstlen = min3(MAX_RX_BURST_LEN, ring_avail(rxfifo), nmdev_avail_rxbufs(nm));
    
    if (burstlen > 0) {
        nmdev_pick_rxbufs(nm, rxbufs, burstlen);
        for (i = 0; i < burstlen; i++) {
            printf("Received %u bytes:\n", *(rxbufs[i].len));
            printh(rxbufs[i].data, (size_t) *(rxbufs[i].len));
        }
        nmdev_put_rxbufs(nm, burstlen);
    }
    
}

static inline void transmit(struct nmdev *nm, struct ring *txfifo)
{
    uint32_t burstlen;
    struct pktbuf *txburst[MAX_TX_BURST_LEN];
    burstlen = min3(MAX_TX_BURST_LEN, ring_count(txfifo), nmdev_avail_txbufs(nm));
    
    if (likely(burstlen > 0)) {
        ring_dequeue_multiple(txfifo, (void **) txburst, burstlen); /* does not fail, because here is the only point
                                                                       where objects are picked from the ring */
        nmdev_xmit_burst(nm, txburst, burstlen);
        statistics_nb_sent_packets += burstlen;
    }
}

struct _ioo_args {
    struct ring *txfifo;
    struct pktbuf *pkts[0];
};

static void handle_cb(struct blkdev *bd, uint64_t sector, size_t nb_sectors, int write, int ret, void *argp)
{
    uint32_t i;
    struct mempool_obj *ioo = argp;
    struct _ioo_args *ioo_args = ioo->private;
    
    if (unlikely(ret < 0)) {
	printf("I/O request @ sector %llu failed: %d\n", sector, ret);
	pktpool_put_multiple(ioo_args->pkts, args.nb_chunks);
	mempool_put(ioo);
	return;
    }
    
    for (i = 0; i < args.nb_chunks; i++) {
	pkt_copy((void *)((uintptr_t) ioo->data + i * args.chunklen), ioo_args->pkts[i]->p_obj.data, args.chunklen);
	ioo_args->pkts[i]->pktlen = args.chunk_pktlen;
	pktbuf_encap_udp_nocheck(ioo_args->pkts[i], &args.src_mac, &args.dst_mac, &args.src_ip, &args.dst_ip, args.src_port, args.dst_port, args.ttl, args.pchksum);
    }
    ring_enqueue_multiple(ioo_args->txfifo, (void **) ioo_args->pkts, args.nb_chunks);
    mempool_put(ioo);
    
    /* update statistics */
    statistics_nb_read_blocks++;
}

static inline void handle(struct ring *rxfifo, struct blkdev *bd, struct mempool *iobpool, struct ring *txfifo, struct mempool *pktpool)
{
    uint32_t burstlen, i;
    static uint64_t addr_s = 0;
    struct mempool_obj *ioo;
    struct _ioo_args *ioo_args;
    
    /* poll for finished requests */
    blkdev_poll_req(bd);
    
    burstlen = min4(MAX_HANDLE_BURST_LEN, (pktpool_free_count(pktpool) / args.nb_chunks), mempool_free_count(iobpool), blkdev_avail_req(bd));
    for (i = 0; i < burstlen; i++) {
	/* Instead of picking up request from rx_fifo, just generate I/O requests */
	if (unlikely(addr_s >= blkdev_sectors(bd)))
            addr_s = 0;
        
	/* submit a new I/O request */
	ioo = mempool_pick(iobpool);
	ioo_args = ioo->private;
	ioo_args->txfifo = txfifo;
	pktpool_pick_multiple(pktpool, ioo_args->pkts, args.nb_chunks);
	blkdev_submit_req_nocheck(bd, addr_s, args.sectors_per_blk, 0, ioo->data, handle_cb, ioo);
        
	addr_s += args.sectors_per_blk;
    }
}

static int parse_decimal(const char *str, int *val)
{
    char *end = NULL;
    int pval;
    
    pval = strtoul(str, &end, 10);
    if ((str[0] == '\0') || (end == NULL) || (*end != '\0'))
        return -1;
    
    *val = pval;
    return 0;
}

static int parse_args(int argc, char **argv) {
    int opt;

    memset(&args, 0, sizeof(args));
    args.ndid = 0; /* first vif/vale device */
    args.bdid = 51712; /* xvda */
    IP4_ADDR((&args.src_ip), 192, 168, 10, 127);
    args.src_port = 6500;
    args.dst_mac.addr[0] = 0xA0;
    args.dst_mac.addr[1] = 0x83;
    args.dst_mac.addr[2] = 0xCC;
    args.dst_mac.addr[3] = 0xEA;
    args.dst_mac.addr[4] = 0x8E;
    args.dst_mac.addr[5] = 0x43;
    IP4_ADDR((&args.dst_ip), 192, 168, 10, 1);
    args.dst_port = 6501;
    args.ttl = PKT_TTL;
    IP4_ADDR((&args.dst_ip), 192, 168, 10, 1);
    args.dst_port = 6501;
    args.ttl = PKT_TTL;
    
    args.blksize = 512;
    
    while ((opt = getopt(argc, argv, "d:b:p:uh")) != -1) {
	switch (opt) {
	case 'b': /* block size */
            if (parse_decimal(optarg, (int *) &args.blksize) ||
                args.blksize < 512 ||
                args.blksize > 32768 ||
                !POWER_OF_2(args.blksize)) {
		printf("invalid block size (has to be a power of 2, at least 512 B, and at most 32 KB)\n");
		return -1;
            }
            break;
	case 'u': /* UDP payload checksum */
            args.pchksum = 1;
            break;
        case 'p': /* additional payload */
            if (parse_decimal(optarg, (int *) &args.addpayload) ||
                args.addpayload < 0 || args.addpayload > (MAX_PKTPAYLOAD - MIN_PKTIOPAYLOAD)) {
		printf("invalid additional payload size (has to be at least %u B and at most %llu B)\n", 0, (MAX_PKTPAYLOAD - MIN_PKTIOPAYLOAD));
		return -1;
            }
            break;
        case 'd': /* block device id */
            if (parse_decimal(optarg, (int *) &args.bdid) || args.bdid < 0) {
                printf("invalid block device id\n", MAX_PKTPAYLOAD);
                return -1;
            }
            break;
        case 'h': /* help */
            return -1;
        default:
            printf("unrecognized option: \"-%c %s\"\n", opt, optarg);
            return -1;
        }
    }
    
    /* Calculate number of chunks and resulting I/O payload per chunk packet */
    args.nb_chunks = 1;
    while (args.blksize / args.nb_chunks > (MAX_PKTPAYLOAD - args.addpayload))
        args.nb_chunks <<= 1;
    args.chunklen = args.blksize / args.nb_chunks;
    args.chunk_pktlen = args.chunklen + args.addpayload;
    
    return 0;
}

static void parse_usage(void)
{
    printf("minicache [-i] [-b BLKSIZE] [-p PLSIZE] [-u] [-d ID] [-n ID]\n");
    printf("\n");
    printf("  -u          Enable calculation of UDP payload checksum\n");
    printf("  -b BLKSIZE  Block size for I/O requests (default=512)\n");
    printf("  -p PLSIZE   Additional payload for each packet (protocol overhead simulation)\n");
    printf("  -d ID       Block device ID to open\n");
}

int main(int argc, char **argv)
{
    struct mempool *pktpool;
    struct mempool *iobpool;
    struct ring *rxfifo;
    struct ring *txfifo;
    struct nmdev *nm;
    struct blkdev *bd;
    uint64_t ts_tick, ts_tock, ts_diff;
    uint64_t nb_rd_blks, nb_tx_pkts;
    uint64_t nb_rd_blks_prev = 0;
    uint64_t nb_tx_pkts_prev = 0;
    int ret;

    /*
     * Arguments
     */
    if (parse_args(argc, argv) < 0) {
	parse_usage();
	return 1;
    }
    
    /* 
     * Initialization
     */
    ret = 1; /* error */
    printf("Opening network device %d\n", args.ndid);
    nm = open_nmdev((unsigned int) args.ndid);
    if (!nm) {
	printf("Could not open network device (vif id: %d): %d\n", args.ndid, errno);
	goto out;
    }
    printf("Network device has MAC address %02x:%02x:%02x:%02x:%02x:%02x\n",
           nmdev_mac(nm)->addr[0], nmdev_mac(nm)->addr[1], nmdev_mac(nm)->addr[2],
           nmdev_mac(nm)->addr[3], nmdev_mac(nm)->addr[4], nmdev_mac(nm)->addr[5]);
    memcpy(args.src_mac.addr, nmdev_mac(nm)->addr, ETHARP_HWADDR_LEN);
    
    printf("Opening block device %d\n", args.bdid);
    bd = open_blkdev((unsigned int) args.bdid, O_RDONLY);
    if (!bd) {
	printf("Could not open block device (vbd id: %d): %d\n", args.bdid, errno);
	goto out_close_nm;
    }
    printf("Block device has sector size of %llu bytes\n", blkdev_ssize(bd));
    printf("Block device has %llu sectors (%llu Mbytes)\n", blkdev_size(bd) / blkdev_ssize(bd), (blkdev_size(bd) >> 20));
    if (args.blksize & (blkdev_ssize(bd) - 1)) {
	printf("Error: Please specify another block size because current block size (%d) is not a multiple of device block size\n", args.blksize);
	goto out_close_bd;
    }
    args.sectors_per_blk = args.blksize / blkdev_ssize(bd);
    
    printf("Allocating RX FIFO\n");
    rxfifo = alloc_ring(RXFIFO_LEN);
    if (!rxfifo) {
	printf("Could not allocate ring 'rxfifo': %d\n", errno);
	goto out_close_bd;
    }
    
    printf("Allocating TX FIFO\n");
    txfifo = alloc_ring(TXFIFO_LEN);
    if (!txfifo) {
	printf("Could not allocate ring 'txfifo': %d\n", errno);
	goto out_free_rxfifo;
    }
    
    printf("Info: Using %u packets per I/O request (blocksize: %llu B; %llu B per packet) with a total payload of %llu B\n", args.nb_chunks, args.blksize, args.chunklen, args.chunk_pktlen);
    printf("Allocating packet buffer pool\n");
    pktpool = alloc_pktpool(PKTPOOL_SIZE, args.chunk_pktlen, 0, PKTENCAP_HDRSIZE, 0);
    if (!pktpool) {
        printf("Could not allocate packet buffer pool 'pktpool': %d\n", errno);
        goto out_free_txfifo;
    }
    
    printf("Allocating I/O buffer pool\n");
    iobpool = alloc_mempool(IOBPOOL_SIZE, args.blksize, blkdev_ssize(bd), 0, 0, NULL, 0, sizeof(struct _ioo_args) + (args.nb_chunks * sizeof(struct pktbuf *)));
    if (!iobpool) {
        printf("Could not allocate I/O buffer pool 'iobpool': %d\n", errno);
        goto out_free_pktpool;
    }
    
    /*
     * Main loop
     */
    ret = 0; /* success */
    printf("Entering main loop...\n");
    printf("%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;%s\n",
           "vbd ID",
           "block size",
           "packet size",
           "packets per block",
           "packet: hdr length",
           "packet: block data length",
           "packet: additional payload",
           "packet: UDP checksum",
           "nb blocks",
           "nb packets",
           "interval len (sec)",
           "timestamp (sec)",
           "/\\nb blocks",
           "/\\nb packets");
    ts_tick = NOW();
    while (1) {
        receive(nm, rxfifo);                          /* puts received pkts (allocated from pktpool) to rxfifo */
        handle(rxfifo, bd, iobpool, txfifo, pktpool); /* transforms rx into submitted ioreqs, finished ioreqs produce a pkt (from pktpool) on txfifo */
        transmit(nm, txfifo);                         /* picks pkts from txfifo, sents them out and releases pktbuf to their pktpool */
        
        /* statistics */
        ts_tock = NOW();
        ts_diff = ts_tock - ts_tick;
        if (unlikely(ts_diff >= (PRINT_STATISTICS_SEC * 1000000000ll))) {
            nb_rd_blks = statistics_nb_read_blocks;
            nb_tx_pkts = statistics_nb_sent_packets;
            printf("%d;%llu;%llu;%llu;%llu;%llu;%llu;%d;%llu;%llu;%llu.%09llu;%llu.%09llu;%llu;%llu\n",
                   args.bdid, /* vdb ID */
                   args.blksize, /* block size */
                   args.chunk_pktlen + PKTENCAP_HDRSIZE + 4, /* packet size (incl. CRC) */
                   args.nb_chunks, /* packets per block */
                   PKTENCAP_HDRSIZE, /* packet: hdr length */
                   args.chunklen, /* packet: block data length */
                   args.addpayload, /* packet: additional payload */
                   args.pchksum ? 1 : 0, /* packet: UDP checksum */
                   nb_rd_blks, /* nb blocks */
                   nb_tx_pkts, /* nb packets */
                   ts_diff / 1000000000, ts_diff % 1000000000, /* interval len (sec) */
                   ts_tick / 1000000000, ts_tick % 1000000000, /* timestamp (sec) */
                   nb_rd_blks - nb_rd_blks_prev,
                   nb_tx_pkts - nb_tx_pkts_prev);
            nb_rd_blks_prev = nb_rd_blks;
            nb_tx_pkts_prev = nb_tx_pkts;
            ts_tick = NOW();
        }
    }
    
    /*
     * Cleanup
     */
    free_mempool(iobpool);
 out_free_pktpool:
    free_pktpool(pktpool);
 out_free_txfifo:
    free_ring(txfifo);
 out_free_rxfifo:
    free_ring(rxfifo);
 out_close_bd:
    close_blkdev(bd);
 out_close_nm:
    close_nmdev(nm);
 out:
    return ret;
}
