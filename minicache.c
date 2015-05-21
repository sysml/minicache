#include <target/sys.h>
#include <target/netdev.h>

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <getopt.h>
#include <sys/time.h>

#include <lwip/ip_addr.h>
#include <netif/etharp.h>
#include <lwip/netif.h>
#include <lwip/inet.h>
#include <lwip/tcp.h>
#include <lwip/tcp_impl.h>
#include <lwip/tcpip.h>
#include <lwip/dhcp.h>
#include <lwip/dns.h>
#include <lwip/ip_frag.h>
#include <lwip/init.h>
#include <lwip/stats.h>

#include "likely.h"
#include "mempool.h"
#include "http.h"
#ifdef IPERF_SERVER
#include "iperf.h"
#endif
#ifdef HAVE_SHELL
#include "shell.h"
#endif
#include "shfs.h"
#include "shfs_tools.h"
#ifdef HAVE_CTLDIR
#include <target/ctldir.h>
#endif
#ifdef SHFS_STATS
#include "shfs_stats.h"
#endif
#ifdef TESTSUITE
#include "testsuite.h"
#endif

#include "debug.h"

/* r = a - b on struct timeval */
#define TV_SUB(r, a, b)							\
	do {									\
		if ((a)->tv_usec < (b)->tv_usec) {				\
			(r)->tv_sec  = (a)->tv_sec  - (b)->tv_sec - 1;		\
			(r)->tv_usec = (a)->tv_usec - (b)->tv_usec + 1000000;	\
		} else {							\
			(r)->tv_sec  = (a)->tv_sec  - (b)->tv_sec;		\
			(r)->tv_usec = (a)->tv_usec - (b)->tv_usec;		\
		}								\
	} while(0)

/* runs (func) a command on a timeout */
#define TIMED(ms_now, ms_till, ms_next, ms_interval, func)	     \
	do {                                                         \
		if (unlikely((ms_next) <= (ms_now))) {		     \
			(ms_next) = (ms_now) + (ms_interval);	     \
			(func);				     \
		}						     \
		/* update ms_till only if current nextin	     \
		 * is smaller than the passed one */		     \
		(ms_till) = (ms_next) < (ms_till) ? (ms_next) : (ms_till); \
	} while(0)

/* boot time tracing helper */
#ifdef TRACE_BOOTTIME
#define TT_DECLARE(var) uint64_t (var) = 0
#define TT_START(var) do { (var) = target_now_ns(); } while(0)
#define TT_END(var) do { (var) = (target_now_ns() - (var)); } while(0)
#define TT_PRINT(desc, var)			\
  printk(" %-32s: %"PRIu64".%06"PRIu64"s\n",		\
	 (desc),				\
	 (var) / 1000000000l,			\
	 ((var) / 1000l) % 1000000l);
#else /* TRACE_BOOTTIME */
#define TT_DECLARE(var) while(0) {}
#define TT_START(var) while(0) {}
#define TT_END(var) while(0) {}
#endif /* TRACE_BOOTTIME */

#ifdef CONFIG_MINDER_PRINT
#define MINDER_INTERVAL 500
static inline void minder_print(void)
{
    static int minder_step = 0;

    switch (minder_step) {
    case 1:
	    printk("\r >))'>   ");
	    minder_step = 2;
	    break;
    case 2:
	    printk("\r  >))'>  ");
	    minder_step = 3;
	    break;
    case 3:
	    printk("\r   >))'> ");
	    minder_step = 4;
	    break;
    case 4:
	    printk("\r    >))'>");
	    minder_step = 5;
	    break;
    case 5:
	    printk("\r    <'((<");
	    minder_step = 6;
	    break;
    case 6:
	    printk("\r   <'((< ");
	    minder_step = 7;
	    break;
    case 7:
	    printk("\r  <'((<  ");
	    minder_step = 8;
	    break;
    case 8:
	    printk("\r <'((<   ");
	    minder_step = 9;
	    break;
    case 9:
	    printk("\r<'((<    ");
	    minder_step = 0;
	    break;
    default:
	    printk("\r>))'>    ");
	    minder_step = 1;
    }
    fflush(stdout);
}
#endif /* CONFIG_MINDER_PRINT */

#define MAX_NB_STATIC_ARP_ENTRIES 6

/**
 * ARGUMENT PARSING
 */
struct mcargs {
    int             dhclient;
    struct eth_addr mac;
    struct ip_addr  ip;
    struct ip_addr  mask;
    struct ip_addr  gw;
    struct ip_addr  dns0;
    struct ip_addr  dns1;
    unsigned int    nb_http_sess;

    int             bd_detect;
    unsigned int    nb_bds;
    blkdev_id_t     bd_id[MAX_NB_TRY_BLKDEVS];
    int             stats_bd;
    blkdev_id_t     stats_bd_id;

    int             no_ctldir;

    unsigned int    startup_delay;

    /* static arp entries can only be added if DHCP is disabled */
    struct {
	    struct ip_addr  ip;
	    struct eth_addr mac;
    } sarp_entry[MAX_NB_STATIC_ARP_ENTRIES];
    unsigned int    nb_sarp_entries;
} args;

static int parse_args_setval_cut(char delimiter, char **out_presnip, char **out_postsnip,
                                 const char *buf)
{
	size_t len = strlen(buf);
	size_t p;

	for (p = 0; p < len; ++p) {
		if (buf[p] == delimiter) {
			*out_presnip = strndup(buf, p);
			*out_postsnip = strdup(&buf[p+1]);
			if (!*out_presnip || !*out_postsnip) {
				if (out_postsnip)
					free(*out_postsnip);
				if (out_presnip)
					free(*out_presnip);
				return -ENOMEM;
			}
			return 0;
		}
	}

	return -1; /* delimiter not found */
}

static int parse_args_setval_ipv4cidr(struct ip_addr *out_ip, struct ip_addr *out_mask, const char *buf)
{
	int ip0, ip1, ip2, ip3;
	int rprefix;
	uint32_t mask;

	if (sscanf(buf, "%d.%d.%d.%d/%d", &ip0, &ip1, &ip2, &ip3, &rprefix) != 5)
		return -1;
	if ((ip0 < 0 || ip0 > 255) ||
	    (ip1 < 0 || ip1 > 255) ||
	    (ip2 < 0 || ip2 > 255) ||
	    (ip3 < 0 || ip3 > 255) ||
	    (rprefix < 0 || rprefix > 32))
		return -1;

	IP4_ADDR(out_ip, ip0, ip1, ip2, ip3);
	if (rprefix == 0)
		mask = 0x0;
	else if (rprefix == 32)
		mask = 0xFFFFFFFF;
	else
		mask = ~((1 << (32 - rprefix)) - 1);
	IP4_ADDR(out_mask,
	         (mask & 0xFF000000) >> 24,
	         (mask & 0x00FF0000) >> 16,
	         (mask & 0x0000FF00) >> 8,
	         (mask & 0x000000FF));
	return 0;
}

static int parse_args_setval_ipv4(struct ip_addr *out, const char *buf)
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

static int parse_args_setval_hwaddr(struct eth_addr *out, const char *buf)
{
	uint8_t hwaddr[6];

	if (sscanf(buf, "%02x:%02x:%02x:%02x:%02x:%02x",
	           &hwaddr[0], &hwaddr[1], &hwaddr[2],
	           &hwaddr[3], &hwaddr[4], &hwaddr[5]) != 6)
		return -1;

	out->addr[0] = hwaddr[0];
	out->addr[1] = hwaddr[1];
	out->addr[2] = hwaddr[2];
	out->addr[3] = hwaddr[3];
	out->addr[4] = hwaddr[4];
	out->addr[5] = hwaddr[5];
	return 0;
}

static int parse_args_setval_int(int *out, const char *buf)
{
	if (sscanf(buf, "%d", out) != 1)
		return -1;
	return 0;
}

static int parse_args(int argc, char *argv[])
{
    char *presnip;
    char *postsnip;
    int opt;
    int ret;
    int ival;
    blkdev_id_t ibd;

    /* default arguments */
    memset(&args, 0, sizeof(args));
    IP4_ADDR(&args.ip,   192, 168, 128, 124);
    IP4_ADDR(&args.mask, 255, 255, 255, 252);
    IP4_ADDR(&args.gw,     0,   0,   0,   0);
    IP4_ADDR(&args.dns0,   0,   0,   0,   0);
    IP4_ADDR(&args.dns1,   0,   0,   0,   0);
    args.nb_bds = 0;
    args.stats_bd = 0; /* disable stats bd */
#ifdef CAN_DETECT_BLKDEVS
    args.bd_detect = 1;
#else
    args.bd_detect = 0;
#endif
    args.dhclient = 1; /* dhcp as default */
    args.startup_delay = 0;
    args.no_ctldir = 0;
    args.nb_http_sess = 500;
#if ((100 + 4) > MEMP_NUM_TCP_PCB)
    #error "MEMP_NUM_TCP_PCB has to be set at least to 104"
#endif
    args.nb_sarp_entries = 0;
    while ((opt = getopt(argc, argv,
                         "s:i:g:d:b:hc:a:"
#ifdef SHFS_STATS
                         "x:"
#endif
                          )) != -1) {
         switch(opt) {
         case 's': /* startup delay */
              ret = parse_args_setval_int(&ival, optarg);
              if (ret < 0 || ival < 0) {
	           printk("invalid delay specified\n");
	           return -1;
              }
              args.startup_delay = (unsigned int) ival;
              break;
         case 'i': /* IP address/mask */
	      ret = parse_args_setval_ipv4cidr(&args.ip, &args.mask, optarg);
	      if (ret < 0) {
	           printk("invalid host IP in CIDR notation specified (e.g., 192.168.0.2/24)\n");
	           return -1;
              }
	      args.dhclient = 0;
              break;
         case 'g': /* gateway */
	      ret = parse_args_setval_ipv4(&args.gw, optarg);
	      if (ret < 0) {
	           printk("invalid gateway IP specified (e.g., 192.168.0.1)\n");
	           return -1;
              }
              break;
         case 'd': /* dns0 */
	      ret = parse_args_setval_ipv4(&args.dns0, optarg);
	      if (ret < 0) {
	           printk("invalid primary DNS IP specified (e.g., 192.168.0.1)\n");
	           return -1;
              }
              break;
         case 'e': /* dns1 */
	      ret = parse_args_setval_ipv4(&args.dns1, optarg);
	      if (ret < 0) {
	           printk("invalid secondary DNS IP specified (e.g., 192.168.0.1)\n");
	           return -1;
              }
              break;
         case 'a': /* static arp entry */
	      if (args.nb_sarp_entries == (MAX_NB_STATIC_ARP_ENTRIES - 1)) {
		   printk("At most %d static ARP entries can be specified\n",
		          MAX_NB_STATIC_ARP_ENTRIES);
		   return -1;
	      }
	      ret = parse_args_setval_cut('/', &presnip, &postsnip, optarg);
	      if (ret < 0) {
		   if (ret == -ENOMEM)
			printk("static ARP parsing error: Out of memory\n");
		   else
			printk("invalid static ARP entry specified (e.g., 01:23:45:67:89:AB/192.168.0.1)\n");
	           return -1;
              }
	      ret = parse_args_setval_hwaddr(&args.sarp_entry[args.nb_sarp_entries].mac, presnip);
	      if (ret < 0) {
	           printk("invalid static ARP entry specified (e.g., 01:23:45:67:89:AB/192.168.0.1)\n");
	           free(postsnip);
	           free(presnip);
	           return -1;
              }
	      ret = parse_args_setval_ipv4(&args.sarp_entry[args.nb_sarp_entries].ip, postsnip);
	      if (ret < 0) {
	           printk("invalid static ARP entry specified (e.g., 01:23:45:67:89:AB/192.168.0.1)\n");
	           free(postsnip);
	           free(presnip);
	           return -1;
              }
	      free(postsnip);
	      free(presnip);
	      args.nb_sarp_entries++;
              break;
         case 'b': /* virtual block device (specified manually to skip detection) */
              if (blkdev_id_parse(optarg, &ibd) < 0) {
	           printk("invalid block device id specified\n");
	           return -1;
              }
	      if (args.nb_bds == sizeof(args.bd_id)) {
		      printk("only %u block devices can be specified\n", sizeof(args.bd_id));
	           return -1;
	      }
	      args.bd_detect = 0; /* disable bd detection */
	      blkdev_id_cpy(args.bd_id[args.nb_bds++], ibd);
              break;
         case 'h': /* hide xenstore control entries */
	      args.no_ctldir = 1;
              break;
#ifdef SHFS_STATS
         case 'x': /* virtual block device for exporting statistics */
              if (blkdev_id_parse(optarg, &ibd) < 0) {
	           printk("invalid block device id specified\n");
	           return -1;
              }
	      if (args.stats_bd) {
		   printk("only one stats devices can be specified\n");
	           return -1;
	      }
	      args.stats_bd = 1; /* enable stats bd */
	      blkdev_id_cpy(args.stats_bd_id, ibd);
              break;
#endif
         case 'c': /* number of http connections */
	      ret = parse_args_setval_int(&ival, optarg);
	      if (ret < 0 || ival < 1 || ival > MEMP_NUM_TCP_PCB - 4) {
		      printk("at most %u http connections supported\n",
		             MEMP_NUM_TCP_PCB - 4);
	           return -1;
	      }
	      args.nb_http_sess = ival;
              break;

         default:
	      return -1;
         }
     }

     return 0;
}

/**
 * SHUTDOWN/SUSPEND
 */
static volatile int shall_shutdown = 0;
static volatile int shall_reboot = 0;
static volatile int shall_suspend = 0;

#ifdef HAVE_SHELL
static int shcmd_halt(FILE *cio, int argc, char *argv[])
{
    shall_reboot = 0;
    shall_shutdown = 1;
    return SH_CLOSE; /* special return code: closes the shell session */
}

static int shcmd_reboot(FILE *cio, int argc, char *argv[])
{
    shall_reboot = 1;
    shall_shutdown = 1;
    return SH_CLOSE;
}

static int shcmd_suspend(FILE *cio, int argc, char *argv[])
{
    shall_suspend = 1;
    return 0;
}
#endif

void app_shutdown(unsigned reason)
{
    switch (reason) {
    case TARGET_SHTDN_POWEROFF:
	    printk("Poweroff requested\n");
	    shall_reboot = 0;
	    shall_shutdown = 1;
	    break;
    case TARGET_SHTDN_REBOOT:
	    printk("Reboot requested\n");
	    shall_reboot = 1;
	    shall_shutdown = 1;
	    break;
    case TARGET_SHTDN_SUSPEND:
	    printk("Suspend requested\n");
	    shall_suspend = 1;
	    break;
    default:
	    printk("Unknown shutdown action requested: %d. Ignoring\n", reason);
	    break;
    }
}

/**
 * MAIN
 */
int main(int argc, char *argv[])
{
    struct netif netif;
    struct netif *niret;
#ifdef HAVE_CTLDIR
    struct ctldir *cd = NULL;
#endif
    int ret;
    err_t err;
    unsigned int i;
#if defined CONFIG_SELECT_POLL && defined CAN_POLL_BLKDEV && defined CAN_POLL_NETDEV
    int poll_netif_fd;
    fd_set poll_rfdset;
    fd_set poll_wfdset;
    struct timeval poll_to;
#endif
#if defined CONFIG_LWIP_NOTHREADS || defined CONFIG_MINDER_PRINT
    uint64_t ts_now;
    uint64_t ts_till;
    uint64_t ts_to;
#endif
#ifdef CONFIG_LWIP_NOTHREADS
    uint64_t ts_tcp = 0;
    uint64_t ts_etharp = 0;
    uint64_t ts_ipreass = 0;
#if LWIP_DNS
    uint64_t ts_dns = 0;
#endif
    uint64_t ts_dhcp_fine = 0;
    uint64_t ts_dhcp_coarse = 0;
#endif /* CONFIG_LWIP_NOTHREADS */
#ifdef CONFIG_MINDER_PRINT
    uint64_t ts_minder = 0;
#endif /* CONFIG_MINDER_PRINT */
    TT_DECLARE(tt_boot);
    TT_DECLARE(tt_netifadd);
    TT_DECLARE(tt_lwipinit);
    TT_DECLARE(tt_bddetect);
#ifdef CONFIG_AUTOMOUNT
    TT_DECLARE(tt_automount);
#endif
    TT_DECLARE(tt_ctldirstart);
#ifdef SHFS_STATS
    TT_DECLARE(tt_statsdev);
#endif
    target_init();

    TT_START(tt_boot);
    init_debug();

    /* -----------------------------------
     * banner
     * ----------------------------------- */
#ifndef CONFIG_HIDE_BANNER
    printk("\n");
    printk("______  _______       ______________            ______       \n");
    printk("___   |/  /__(_)_________(_)_  ____/_____ _________  /______ \n");
    printk("__  /|_/ /__  /__  __ \\_  /_  /    _  __ `/  ___/_  __ \\  _ \\\n");
    printk("_  /  / / _  / _  / / /  / / /___  / /_/ // /__ _  / / /  __/\n");
    printk("/_/  /_/  /_/  /_/ /_//_/  \\____/  \\__,_/ \\___/ /_/ /_/\\___/ \n");
#ifdef CONFIG_BANNER_VERSION
    printk("%61s\n", ""CONFIG_BANNER_VERSION"");
#endif
    printk("\n");
    printk("Copyright(C) 2013-2015 NEC Europe Ltd.\n");
    printk("Authors: Simon Kuenzer <simon.kuenzer@neclab.eu>\n");
    printk("\n");
#endif

    /* -----------------------------------
     * argument parsing
     * ----------------------------------- */
    if (parse_args(argc, argv) < 0) {
	    printk("Argument parsing error!\n" \
	           "Please check your arguments\n");
	    goto out;
    }

    if (args.startup_delay) {
	    unsigned int s;
	    printk("Startup delay");
	    fflush(stdout);
	    for (s = 0; s < args.startup_delay; ++s) {
		    printf(".");
		    fflush(stdout);
		    msleep(1000);
	    }
	    printk("\n");
    }

    /* -----------------------------------
     * control dir - phase 1/2
     * ----------------------------------- */
#ifdef HAVE_CTLDIR
    if (!args.no_ctldir) {
	    printk("Initialize xenstore control entries...\n");
	    cd = create_ctldir("minicache");
	    if (!cd) {
		    printk("Warning: Could not initialize xenstore control entries: %s\n", strerror(errno));
		    printk("         Disabling xenstore cotrol entries\n");
	    }
    }
#endif

    /* -----------------------------------
     * detect available block devices
     * ----------------------------------- */
#ifdef CAN_DETECT_BLKDEVS
    if (args.bd_detect) {
	    printk("Detecting block devices...\n");
	    TT_START(tt_bddetect);
	    args.nb_bds = detect_blkdevs(args.bd_id, sizeof(args.bd_id));
	    TT_END(tt_bddetect);
    }
#endif

    /* -----------------------------------
     * filesystem initialization & automount
     * ----------------------------------- */
    printk("Loading SHFS...\n");
    init_shfs();
#ifdef CONFIG_AUTOMOUNT
    if (args.nb_bds) {
	    printk("Automount cache filesystem...\n");
	    TT_START(tt_automount);
	    ret = mount_shfs(args.bd_id, args.nb_bds);
	    TT_END(tt_automount);
	    if (ret < 0)
		    printk("Warning: Could not find or mount a cache filesystem\n");
    }
#endif

    /* -----------------------------------
     * lwIP initialization
     * ----------------------------------- */
    printk("Starting networking...\n");
    TT_START(tt_lwipinit);
#ifdef CONFIG_LWIP_NOTHREADS
    lwip_init();
#else
    tcpip_init(NULL, NULL);
#endif
    TT_END(tt_lwipinit);

    /* -----------------------------------
     * network interface initialization
     * ----------------------------------- */
    TT_START(tt_netifadd);
    /* NOTE: IP-level devices are currently only
     * supported in non-threaded env */
#ifdef CONFIG_LWIP_NOTHREADS
#ifdef CONFIG_LWIP_IPDEV
    niret = netif_add(&netif, &args.ip, &args.mask, &args.gw, NULL,
                      target_netif_init, ip_input);
#else
    niret = netif_add(&netif, &args.ip, &args.mask, &args.gw, NULL,
                      target_netif_init, ethernet_input);
#endif
#else /* CONFIG_LWIP_NOTHREADS */
    niret = netif_add(&netif, &args.ip, &args.mask, &args.gw, NULL,
                      target_netif_init, tcpip_input);
#endif /* CONFIG_LWIP_NOTHREADS */
    TT_END(tt_netifadd);

    /* device init function is user-defined
     * use ip_input instead of ethernet_input for non-ethernet hardware
     * (this function is assigned to netif.input and should be called by
     * the hardware driver) */
    /*
     * The final parameter input is the function that a driver will
     * call when it has received a new packet. This parameter
     * typically takes one of the following values:
     * ethernet_input: If you are not using a threaded environment
     *                 and the driver should use ARP (such as for
     *                 an Ethernet device), the driver will call
     *                 this function which permits ARP packets to
     *                 be handled, as well as IP packets.
     * ip_input:       If you are not using a threaded environment
     *                 and the interface is not an Ethernet device,
     *                 the driver will directly call the IP stack.
     * tcpip_ethinput: If you are using the tcpip application thread
     *                 (see lwIP and threads), the driver uses ARP,
     *                 and has defined the ETHARP_TCPIP_ETHINPUT lwIP
     *                 option. This function is used for drivers that
     *                 passes all IP and ARP packets to the input function.
     * tcpip_input:    If you are using the tcpip application thread
     *                 and have defined ETHARP_TCPIP_INPUT option.
     *                 This function is used for drivers that pass
     *                 only IP packets to the input function.
     *                 (The driver probably separates out ARP packets
     *                 and passes these directly to the ARP module).
     *                 (Someone please recheck this: in lwip 1.4.1
     *                 there is no tcpip_ethinput() ; tcp_input()
     *                 handles ARP packets as well).
     */
    if (!niret) {
        printk("FATAL: Could not initialize the network interface\n");
        goto out;
    }
    netif_set_default(&netif);
    netif_set_up(&netif);
#if defined CONFIG_SELECT_POLL && defined CAN_POLL_BLKDEV && defined CAN_POLL_NETDEV
    poll_netif_fd = target_netif_fd(&netif);
#endif
    if (args.dhclient) {
	printk("Starting DHCP client (background)...\n");
        dhcp_start(&netif);
    } else {
	for (i = 0; i < args.nb_sarp_entries; ++i) {
	    err = etharp_add_static_entry(&args.sarp_entry[i].ip, &args.sarp_entry[i].mac);
	    if (err != ERR_OK) {
	        printk("Could not add static ARP entry: %02x:%02x:%02x:%02x:%02x:%02x\n",
	               args.sarp_entry[i].mac.addr[0],
	               args.sarp_entry[i].mac.addr[1],
	               args.sarp_entry[i].mac.addr[2],
	               args.sarp_entry[i].mac.addr[3],
	               args.sarp_entry[i].mac.addr[4],
	               args.sarp_entry[i].mac.addr[5]);
	    }
	}
    }

    /* -----------------------------------
     * service initialization
     * ----------------------------------- */
#ifdef HAVE_SHELL
    printk("Starting shell...\n");
    init_shell(0, 4); /* no local session + 4 telnet sessions */
#endif
    printk("Starting HTTP server (max number of connections: %u)...\n",
           args.nb_http_sess);
    init_http(args.nb_http_sess,
              args.nb_http_sess + args.nb_http_sess / 2);
#ifdef IPERF_SERVER
    printk("Starting IPERF server...\n");
    register_iperfsrv();
#endif

    /* add custom commands to the shell */
#ifdef HAVE_SHELL
    shell_register_cmd("halt", shcmd_halt);
    shell_register_cmd("reboot", shcmd_reboot);
    shell_register_cmd("suspend", shcmd_suspend);
#ifdef HAVE_CTLDIR
    register_shfs_tools(cd); /* Note: cd might be NULL */
#else
    register_shfs_tools();
#endif
#endif

#ifdef SHFS_STATS
    /* -----------------------------------
     * stats device
     * ----------------------------------- */
    printk("Initializing stats device...\n");
    if(args.stats_bd) {
	TT_START(tt_statsdev);
	ret = init_shfs_stats_export(args.stats_bd_id);
	TT_END(tt_statsdev);
	if (ret < 0) {
	    printk("Warning: Could not open stats device: %s\n", strerror(-ret));
	    args.stats_bd = 0;
	}
    }

#ifdef HAVE_CTLDIR
    register_shfs_stats_tools(cd); /* Note: cd might be NULL */
#else
    register_shfs_stats_tools();
#endif
#endif /* SHFS_STATS */

    /* -----------------------------------
     * testsuite commands
     * ----------------------------------- */
#ifdef TESTSUITE
#ifdef HAVE_CTLDIR
    register_testsuite(cd); /* Note: cd might be NULL */
#else
    register_testsuite();
#endif
#endif

    /* -----------------------------------
     * control dir - phase 2/2
     * ----------------------------------- */
#ifdef HAVE_CTLDIR
    if (cd) {
	    printk("Registering xenstore control entries...\n");
	    TT_START(tt_ctldirstart);
	    ret = ctldir_start_watcher(cd);
	    TT_END(tt_ctldirstart);
	    if (ret < 0) {
		    printk("FATAL: Could not register xenstore control entries: %s\n", strerror(-ret));
		    goto out;
	    }
    }
#endif

    /* -----------------------------------
     * Initialize select/poll
     * ----------------------------------- */
#if defined CONFIG_SELECT_POLL && defined CAN_POLL_BLKDEV && defined CAN_POLL_NETDEV
    FD_ZERO(&poll_rfdset);
    FD_ZERO(&poll_wfdset);
    ts_to = 0;
#endif

    /* -----------------------------------
     * Boot banner/time trace output
     * ----------------------------------- */
    printk("*** MiniCache is up and running ***\n");
#ifdef TRACE_BOOTTIME
    TT_END(tt_boot);
    TT_PRINT("boot time since invoking main", tt_boot);
    TT_PRINT("lwip initialization", tt_lwipinit);
    TT_PRINT("vif addition", tt_netifadd);
    if (args.bd_detect)
	    TT_PRINT("virtual block device detection", tt_bddetect);
#ifdef CONFIG_AUTOMOUNT
    if (args.nb_bds)
	    TT_PRINT("file system mount time", tt_automount);
#endif
#ifdef SHFS_STATS
    if (args.stats_bd)
	    TT_PRINT("stats device initialization", tt_statsdev);
#endif
#ifdef HAVE_CTLDIR
    if (cd)
	    TT_PRINT("xenstore registration", tt_ctldirstart);
#endif
    printk("***\n");
#endif /* TRACE_BOOTTIME */
#ifdef CONFIG_MINDER_PRINT
    printk("\n");
#endif

    /* -----------------------------------
     * Processing loop
     * ----------------------------------- */
    while(likely(!shall_shutdown)) {
#if defined CONFIG_SELECT_POLL && defined CAN_POLL_BLKDEV && defined CAN_POLL_NETDEV
	/* select with ignoring return reason */
	FD_SET(poll_netif_fd, &poll_rfdset);
#if defined CONFIG_LWIP_NOTHREADS || defined CONFIG_MINDER_PRINT
	if (likely(ts_to)) {
		poll_to.tv_sec = ts_to / 1000;
		poll_to.tv_usec = (ts_to % 1000) * 1000;
#else
		poll_to.tv_sec  = 0;
		poll_to.tv_usec = 0;
#endif
		if (shfs_mounted) {
			/* poll network and block devices */
			shfs_blkdevs_fdset(&poll_rfdset);
			select(max(shfs_vol.members_maxfd, poll_netif_fd) + 1,
			       &poll_rfdset, &poll_wfdset, NULL, &poll_to);
			} else {
				/* poll network only */
			select(poll_netif_fd + 1, &poll_rfdset, NULL, NULL, &poll_to);
		}
#if defined CONFIG_LWIP_NOTHREADS || defined CONFIG_MINDER_PRINT
	}
#endif
#else
	schedule(); /* yield CPU */
#endif

	/* poll block devices */
	shfs_poll_blkdevs();

	/* poll IO retry chain of HTTP */
	http_poll_ioretry();

#ifdef CONFIG_LWIP_NOTHREADS
        /* NIC handling loop (single threaded lwip) */
	target_netif_poll(&netif);
#endif /* CONFIG_LWIP_NOTHREADS */

#if defined CONFIG_LWIP_NOTHREADS || defined CONFIG_MINDER_PRINT
        ts_now  = NSEC_TO_MSEC(target_now_ns());
	ts_till = UINT64_MAX;
#endif
#ifdef CONFIG_LWIP_NOTHREADS
	/* Process lwip network-related timers */
        TIMED(ts_now, ts_till, ts_etharp,  ARP_TMR_INTERVAL, etharp_tmr());
        TIMED(ts_now, ts_till, ts_ipreass, IP_TMR_INTERVAL,  ip_reass_tmr());
        TIMED(ts_now, ts_till, ts_tcp,     TCP_TMR_INTERVAL, tcp_tmr());
#if LWIP_DNS
        TIMED(ts_now, ts_till, ts_dns,     DNS_TMR_INTERVAL, dns_tmr());
#endif
        if (args.dhclient) {
	        TIMED(ts_now, ts_till, ts_dhcp_fine,   DHCP_FINE_TIMER_MSECS,   dhcp_fine_tmr());
	        TIMED(ts_now, ts_till, ts_dhcp_coarse, DHCP_COARSE_TIMER_MSECS, dhcp_coarse_tmr());
        }
#endif /* CONFIG_LWIP_NOTHREADS */
#ifdef CONFIG_MINDER_PRINT
        TIMED(ts_now, ts_till, ts_minder,  MINDER_INTERVAL,  minder_print());
#endif /* CONFIG_MINDER_PRINT */
#if defined CONFIG_LWIP_NOTHREADS || defined CONFIG_MINDER_PRINT
        ts_to = ts_till - ts_now;
#endif

        if (unlikely(shall_suspend)) {
            printk("System is going to suspend now\n");
            netif_set_down(&netif);
            netif_remove(&netif);

            target_suspend();

            printk("System woke up from suspend\n");
            netif_set_default(&netif);
            netif_set_up(&netif);
            if (args.dhclient)
                dhcp_start(&netif);
            shall_suspend = 0;
        }
    }

    /* -----------------------------------
     * Shutdown
     * ----------------------------------- */
    if (shall_reboot)
	    printk("System is going down to reboot now\n");
    else
	    printk("System is going down to halt now\n");
#ifdef SHFS_STATS
    if (args.stats_bd) {
	    printk("Closing stats device...\n");
	    exit_shfs_stats_export();
    }
#endif
#ifdef IPERF_SERVER
    printk("Stopping IPERF server...\n");
    unregister_iperfsrv();
#endif
    printk("Stopping HTTP server...\n");
    exit_http();
#ifdef HAVE_SHELL
    printk("Stopping shell...\n");
    exit_shell();
#endif
    printk("Unmounting cache filesystem...\n");
    umount_shfs(0); /* we cannot enforce unmount but all files should be closed here anyways */
    exit_shfs();
    printk("Stopping networking...\n");
    netif_set_down(&netif);
    netif_remove(&netif);
 out:
    if (shall_reboot)
        target_reboot();
    target_halt();

    target_exit();
    return 0;
}
