#include <mini-os/os.h>
#include <mini-os/types.h>
#include <mini-os/xmalloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <getopt.h>
#include <kernel.h>
#include <sched.h>
#include <pkt_copy.h>
#include <mempool.h>
#include <semaphore.h>

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

#ifdef CONFIG_NMWRAP
#include <lwip-nmwrap.h>
#else
#include <lwip-netfront.h>
#endif

#include "http.h"
#include "shell.h"
#include "shfs.h"
#include "shfs_tools.h"
#include "ctldir.h"

#include "debug.h"

#define MAX_NB_VBD 64
#ifdef CONFIG_LWIP_SINGLETHREADED
#define RXBURST_LEN (LNMW_MAX_RXBURST_LEN)
#endif /* CONFIG_LWIP_MINIMAL */

/* runs (func) a command on a timeout */
#define TIMED(ts_now, ts_tmr, interval, func)                        \
	do {                                                         \
		if (unlikely(((ts_now) - (ts_tmr)) > (interval))) {  \
			if ((ts_tmr))                                \
				(func);                              \
			(ts_tmr) = (ts_now);                         \
		}                                                    \
	} while(0)

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

/**
 * ARGUMENT PARSING
 */
static struct _args {
    int             dhclient;
    struct eth_addr mac;
    struct ip_addr  ip;
    struct ip_addr  mask;
    struct ip_addr  gw;
    struct ip_addr  dns0;
    struct ip_addr  dns1;

    unsigned int    nb_vbds;
    unsigned int    vbd_id[32];
    int             vbd_detect;

    unsigned int    startup_delay;
} args;

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

static int parse_args_setval_int(int *out, const char *buf)
{
	if (sscanf(buf, "%d", out) != 1)
		return -1;
	return 0;
}

static int parse_args(int argc, char *argv[])
{
    int opt;
    int ret;
    int ival;

    /* default arguments */
    memset(&args, 0, sizeof(args));
    IP4_ADDR(&args.ip,   192, 168, 128, 124);
    IP4_ADDR(&args.mask, 255, 255, 255, 252);
    IP4_ADDR(&args.gw,     0,   0,   0,   0);
    IP4_ADDR(&args.dns0,   0,   0,   0,   0);
    IP4_ADDR(&args.dns1,   0,   0,   0,   0);
    args.nb_vbds = 0;
    args.vbd_detect = 1;
    args.dhclient = 1; /* dhcp as default */
    args.startup_delay = 0;

     while ((opt = getopt(argc, argv, "s:i:g:d:b:")) != -1) {
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
	      if (ret < 0 || ival < 0) {
	           printk("invalid host IP in CIDR notation specified (e.g., 192.168.0.2/24)\n");
	           return -1;
              }
	      args.dhclient = 0;
              break;
         case 'g': /* gateway */
	      ret = parse_args_setval_ipv4(&args.gw, optarg);
	      if (ret < 0 || ival < 0) {
	           printk("invalid gateway IP specified (e.g., 192.168.0.1)\n");
	           return -1;
              }
              break;
         case 'd': /* dns0 */
	      ret = parse_args_setval_ipv4(&args.dns0, optarg);
	      if (ret < 0 || ival < 0) {
	           printk("invalid primary DNS IP specified (e.g., 192.168.0.1)\n");
	           return -1;
              }
              break;
         case 'e': /* dns1 */
	      ret = parse_args_setval_ipv4(&args.dns1, optarg);
	      if (ret < 0 || ival < 0) {
	           printk("invalid secondary DNS IP specified (e.g., 192.168.0.1)\n");
	           return -1;
              }
              break;
         case 'b': /* virtual block device (specified manually to skip detection) */
	      ret = parse_args_setval_int(&ival, optarg);
	      if (ret < 0 || ival < 0) {
	           printk("invalid block device id specified\n");
	           return -1;
              }
	      if (args.nb_vbds == sizeof(args.vbd_id)) {
		      printk("only %u block devices can be specified\n", sizeof(args.vbd_id));
	           return -1;
	      }
	      args.vbd_detect = 0; /* disable vbd detection */
	      args.vbd_id[args.nb_vbds++] = (unsigned int) ival;
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

void app_shutdown(unsigned reason)
{
    switch (reason) {
    case SHUTDOWN_poweroff:
	    printk("Poweroff requested\n", reason);
	    shall_reboot = 0;
	    shall_shutdown = 1;
	    break;
    case SHUTDOWN_reboot:
	    printk("Reboot requested: %d\n", reason);
	    shall_reboot = 1;
	    shall_shutdown = 1;
	    break;
    case SHUTDOWN_suspend:
	    printk("Suspend requested: %d\n", reason);
	    shall_suspend = 1;
	    break;
    default:
	    printk("Unknown shutdown action requested: %d. Ignoring\n", reason);
	    break;
    }
}

/**
 * VBD MGMT
 */
static int shcmd_lsvbd(FILE *cio, int argc, char *argv[])
{
    unsigned int vbd_id[32];
    unsigned int nb_vbds;
    struct blkdev *bd;
    unsigned int i;

    nb_vbds = detect_blkdevs(vbd_id, sizeof(vbd_id));

    for (i = 0; i < nb_vbds; ++i) {
	    bd = open_blkdev(vbd_id[i], 0x0);

	    if (bd) {
		    fprintf(cio, " %u: block size = %lu bytes, size = %lu bytes%s\n",
		            vbd_id[i],
		            blkdev_ssize(bd),
		            blkdev_size(bd),
		            bd->refcount >= 2 ? ", in use" : "");
		    close_blkdev(bd);
	    } else {
		    if (errno == EBUSY)
			    fprintf(cio, " %u: in exclusive use\n", vbd_id[i]);
	    }
    }
    return 0;
}

#if LWIP_STATS_DISPLAY
#include <lwip/stats.h>

static int shcmd_lwipstats(FILE *cio, int argc, char *argv[])
{
	stats_display();
	return 0;
}
#endif

static int shcmd_ifconfig(FILE *cio, int argc, char *argv[])
{
	struct netif *netif;
	int is_up;
	uint8_t flags;

	for (netif = netif_list; netif != NULL; netif = netif->next) {
		is_up = netif_is_up(netif);
		flags = netif->flags;

		/* name + mac */
		fprintf(cio, "%c%c%c%c      ",
		        (netif->name[0] ? netif->name[0] : ' '),
		        (netif->name[1] ? netif->name[1] : ' '),
		        (netif->name[2] ? netif->name[2] : ' '),
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
		if (flags & NETIF_FLAG_POINTTOPOINT)
			fprintf(cio, "P2P ");
		if (flags & NETIF_FLAG_DHCP)
			fprintf(cio, "DHCP ");
		if (flags & NETIF_FLAG_ETHARP)
			fprintf(cio, "ARP ");
		if (flags & NETIF_FLAG_ETHERNET)
			fprintf(cio, "ETHERNET ");
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

/**
 * MAIN
 */
int main(int argc, char *argv[])
{
    struct netif netif;
    struct ctldir *cd;
    int ret;
#if defined CONFIG_LWIP_SINGLETHREADED || defined CONFIG_MINDER_PRINT
    uint64_t now;
#endif
#ifdef CONFIG_LWIP_SINGLETHREADED
    uint64_t ts_tcp = 0;
    uint64_t ts_etharp = 0;
    uint64_t ts_ipreass = 0;
    uint64_t ts_dns = 0;
    uint64_t ts_dhcp_fine = 0;
    uint64_t ts_dhcp_coarse = 0;
#endif /* CONFIG_LWIP_SINGLETHREADED */
#ifdef CONFIG_MINDER_PRINT
    uint64_t ts_minder = 0;
#endif /* CONFIG_MINDER_PRINT */

    init_debug();

    /* -----------------------------------
     * banner
     * ----------------------------------- */
#ifndef CONFIG_HIDE_BANNER
    printk("\n");
    printk("_|      _|  _|            _|    _|_|_|                      _|                \n");
    printk("_|_|  _|_|      _|_|_|        _|          _|_|_|    _|_|_|  _|_|_|      _|_|  \n");
    printk("_|  _|  _|  _|  _|    _|  _|  _|        _|    _|  _|        _|    _|  _|_|_|_|\n");
    printk("_|      _|  _|  _|    _|  _|  _|        _|    _|  _|        _|    _|  _|      \n");
    printk("_|      _|  _|  _|    _|  _|    _|_|_|    _|_|_|    _|_|_|  _|    _|    _|_|_|\n");
    printk("\n");
    printk("Copyright(C) 2013-1014 NEC Laboratories Europe Ltd.\n");
    printk("                       Simon Kuenzer <simon.kuenzer@neclab.eu>\n");
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
	    printf("\n");
    }

    /* -----------------------------------
     * detect available block devices
     * ----------------------------------- */
    if (args.vbd_detect) {
	    printk("Detecting block devices...\n");
	    args.nb_vbds = detect_blkdevs(args.vbd_id, sizeof(args.vbd_id));
    }

    /* -----------------------------------
     * lwIP initialization
     * ----------------------------------- */
    printk("Starting networking...\n");
#ifdef CONFIG_LWIP_SINGLETHREADED
    lwip_init(); /* single threaded */
#else
    tcpip_init(NULL, NULL); /* multi-threaded */
#endif

    /* -----------------------------------
     * network interface initialization
     * ----------------------------------- */
#ifdef CONFIG_LWIP_SINGLETHREADED
#ifdef CONFIG_NMWRAP
    if (!netif_add(&netif, &args.ip, &args.mask, &args.gw, NULL,
                   nmwif_init, ethernet_input)) {
#else
    if (!netif_add(&netif, &args.ip, &args.mask, &args.gw, NULL,
                   netfrontif_init, ethernet_input)) {
#endif /* CONFIG_NMWRAP */
#else
#ifdef CONFIG_NMWRAP
    if (!netif_add(&netif, &args.ip, &args.mask, &args.gw, NULL,
                   nmwif_init, tcpip_input)) {
#else
    if (!netif_add(&netif, &args.ip, &args.mask, &args.gw, NULL,
                   netfrontif_init, tcpip_input)) {
#endif /* CONFIG_NMWRAP */

#endif /* CONFIG_LWIP_SINGLETHREADED */
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
        printk("FATAL: Could not initialize the network interface\n");
        goto out;
    }
    netif_set_default(&netif);
    netif_set_up(&netif);
    if (args.dhclient) {
	printk("Starting DHCP client (background)...\n");
        dhcp_start(&netif);
    }

    /* -----------------------------------
     * filesystem automount
     * ----------------------------------- */
    printk("Loading SHFS...\n");
    init_shfs();
#ifdef CONFIG_AUTOMOUNT
    printk("Automount cache filesystem...\n");
    ret = mount_shfs(args.vbd_id, args.nb_vbds);
    if (ret < 0)
	    printk("Warning: Could not find or mount a cache filesystem\n");
#endif

    /* -----------------------------------
     * service initialization
     * ----------------------------------- */
    printk("Starting shell...\n");
    init_shell(0, 4); /* no local session + 4 telnet sessions */
    printk("Starting HTTP server...\n");
    init_http(60); /* allow 60 simultaneous connections */

    /* add custom commands to the shell */
    shell_register_cmd("halt", shcmd_halt);
    shell_register_cmd("reboot", shcmd_reboot);
    shell_register_cmd("suspend", shcmd_suspend);
    shell_register_cmd("lsvbd", shcmd_lsvbd);
    shell_register_cmd("ifconfig", shcmd_ifconfig);
    register_shfs_tools();
#if LWIP_STATS_DISPLAY
    shell_register_cmd("lwip-stats", shcmd_lwipstats);
#endif

    /* -----------------------------------
     * Processing loop
     * ----------------------------------- */
    printk("*** MiniCache is up and running ***\n");
#ifdef CONFIG_MINDER_PRINT
    printk("\n");
#endif
    while(likely(!shall_shutdown)) {
	/* poll block devices */
	shfs_poll_blkdevs();

#ifdef CONFIG_LWIP_SINGLETHREADED
        /* NIC handling loop (single threaded lwip) */
#ifdef CONFIG_NMWRAP
	nmwif_handle(&netif, RXBURST_LEN);
#else
	netfrontif_handle(&netif, RXBURST_LEN);
#endif /* CONFIG_NMWRAP */
#endif /* CONFIG_LWIP_SINGLETHREADED */

#if defined CONFIG_LWIP_SINGLETHREADED || defined CONFIG_MINDER_PRINT
        now = NSEC_TO_MSEC(NOW());
#endif
#ifdef CONFIG_LWIP_SINGLETHREADED
	/* Process lwip network-related timers */
        TIMED(now, ts_etharp,  ARP_TMR_INTERVAL, etharp_tmr());
        TIMED(now, ts_ipreass, IP_TMR_INTERVAL,  ip_reass_tmr());
        TIMED(now, ts_tcp,     TCP_TMR_INTERVAL, tcp_tmr());
        TIMED(now, ts_dns,     DNS_TMR_INTERVAL, dns_tmr());
        if (args.dhclient) {
	        TIMED(now, ts_dhcp_fine,   DHCP_FINE_TIMER_MSECS,   dhcp_fine_tmr());
	        TIMED(now, ts_dhcp_coarse, DHCP_COARSE_TIMER_MSECS, dhcp_coarse_tmr());
        }
#endif /* CONFIG_LWIP_SINGLETHREADED */
#ifdef CONFIG_MINDER_PRINT
        TIMED(now, ts_minder,  MINDER_INTERVAL,  minder_print());
#endif /* CONFIG_MINDER_PRINT */
        schedule(); /* yield CPU */

        if (unlikely(shall_suspend)) {
            printk("System is going to suspend now\n");
            netif_set_down(&netif);
            netif_remove(&netif);

            kernel_suspend();

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
    printk("Stopping HTTP server...\n");
    exit_http();
    printk("Stopping shell...\n");
    exit_shell();
    printk("Unmounting cache filesystem...\n");
    umount_shfs();
    exit_shfs();
    printk("Stopping networking...\n");
    netif_set_down(&netif);
    netif_remove(&netif);
 out:
    if (shall_reboot)
	    kernel_poweroff(SHUTDOWN_reboot);
    kernel_poweroff(SHUTDOWN_poweroff);

    return 0; /* will never be reached */
}
