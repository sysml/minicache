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

#include <ipv4/lwip/ip_addr.h>
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

#include "httpd.h"
#include "shell.h"
#include "shfs.h"
#include "shfs_tools.h"

#define MAX_NB_VBD 64
#ifdef CONFIG_LWIP_SINGLETHREADED
#define RXBURST_LEN (LNMW_MAX_RXBURST_LEN)
/* runs (func) a command on a timeout */
#define TIMED(ts_now, ts_tmr, interval, func)                        \
	do {                                                         \
		if (unlikely(((ts_now) - (ts_tmr)) >= (interval))) { \
			if ((ts_tmr))                                \
				(func);                              \
			(ts_tmr) = (ts_now);                         \
		}                                                    \
	} while(0)
#endif /* CONFIG_LWIP_MINIMAL */

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
    unsigned int    vbd_id[16];
    unsigned int    startup_delay;
} args;

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
    IP4_ADDR(&args.ip,   10,  10,  10,  1);
    IP4_ADDR(&args.mask, 255, 255, 255, 0);
    IP4_ADDR(&args.gw,   0,   0,   0,   0);
    IP4_ADDR(&args.dns0, 0,   0,   0,   0);
    IP4_ADDR(&args.dns1, 0,   0,   0,   0);
    args.nb_vbds = 4;
    args.vbd_id[0] = 51712; /* xvda */
    args.vbd_id[1] = 51728; /* xvdb */
    args.vbd_id[2] = 51744; /* xvdc */
    args.vbd_id[3] = 51760; /* xvdd */
    args.dhclient = 0;
    args.startup_delay = 0;

     while ((opt = getopt(argc, argv, "s:")) != -1) {
         switch(opt) {
         case 's': /* startup delay */
              ret = parse_args_setval_int(&ival, optarg);
              if (ret < 0 || ival < 0) {
	           printf("invalid delay specified\n");
	           return -1;
              }
              args.startup_delay = (unsigned int) ival;
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
	    printf("Poweroff requested\n", reason);
	    shall_reboot = 0;
	    shall_shutdown = 1;
	    break;
    case SHUTDOWN_reboot:
	    printf("Reboot requested: %d\n", reason);
	    shall_reboot = 1;
	    shall_shutdown = 1;
	    break;
    case SHUTDOWN_suspend:
	    printf("Suspend requested: %d\n", reason);
	    shall_suspend = 1;
	    break;
    default:
	    printf("Unknown shutdown action requested: %d. Ignoring\n", reason);
	    break;
    }
}

/**
 * VBD MGMT
 */
struct semaphore _vbd_lock;

static int shcmd_lsvbd(FILE *cio, int argc, char *argv[])
{
    struct blkdev *bd;
    unsigned int i ,j;
    int inuse;

    down(&_vbd_lock);
    for (i = 0; i < args.nb_vbds; ++i) {
	    /* because blkfront does not support opening the same device for
	     * multiple times, we need to check if a device was already
	     * opened by SHFS */
	    inuse = 0;
	    bd = NULL;
	    if (shfs_mounted)
		    for (j = 0; j < shfs_vol.nb_members; ++j) {
			    if (shfs_vol.member[j].bd->vbd_id == args.vbd_id[i]) {
				    bd = shfs_vol.member[j].bd;
				    inuse = 1;
				    break;
			    }
		    }
	    if (!bd)
		    bd = open_blkdev(args.vbd_id[i], O_RDONLY);

	    if (bd) {
		    fprintf(cio, " %u: block size = %lu bytes, size = %lu bytes%s\n",
		            args.vbd_id[i],
		            blkdev_ssize(bd),
		            blkdev_size(bd),
		            inuse ? ", inuse" : "");

		    if (!inuse)
			    close_blkdev(bd);
	    }
    }
    up(&_vbd_lock);
    return 0;
}

static int shcmd_mount_shfs(FILE *cio, int argc, char *argv[])
{
    unsigned int vbd_id[MAX_NB_TRY_BLKDEVS];
    unsigned int count;
    unsigned int i, j;
    int ret;

    if ((argc + 1) > MAX_NB_TRY_BLKDEVS) {
	    fprintf(cio, "At most %u devices are supported\n", MAX_NB_TRY_BLKDEVS);
	    return -1;
    }
    if ((argc) == 1) {
	    fprintf(cio, "Usage: %s [vbd_id]...\n", argv[0]);
	    return -1;
    }
    for (i = 1; i < argc; ++i) {
	    if (sscanf(argv[i], "%u", &vbd_id[i - 1]) != 1) {
		    fprintf(cio, "Invalid argument %u\n", i);
		    return -1;
	    }
    }
    count = argc - 1;

    /* search for duplicates in the list
     * This is unfortunately a ugly & slow way doing it... */
    for (i = 0; i < count; ++i)
	    for (j = 0; j < count; ++j)
		    if (i != j && vbd_id[i] == vbd_id[j]) {
			    fprintf(cio, "Found duplicates in the list\n");
			    return -1;
		    }

    down(&_vbd_lock);
    if (shfs_mounted) {
	    fprintf(cio, "A filesystem is already mounted\nPlease unmount it first\n");
	    up(&_vbd_lock);
	    return -1;
    }
    ret = mount_shfs(vbd_id, count);
    if (ret < 0)
	    fprintf(cio, "Mounting failed\n");
    up(&_vbd_lock);
    return ret;
}

static int shcmd_umount_shfs(FILE *cio, int argc, char *argv[])
{
    down(&_vbd_lock);
    umount_shfs();
    up(&_vbd_lock);
    return 0;
}

/**
 * MAIN
 */
int main(int argc, char *argv[])
{
    struct netif netif;
    int ret;
#ifdef CONFIG_LWIP_SINGLETHREADED
    uint64_t now;
    uint64_t ts_tcp = 0;
    uint64_t ts_etharp = 0;
    uint64_t ts_ipreass = 0;
    uint64_t ts_dns = 0;
    uint64_t ts_dhcp_fine = 0;
    uint64_t ts_dhcp_coarse = 0;
#endif

    init_SEMAPHORE(&_vbd_lock, 1);

    /* -----------------------------------
     * argument parsing
     * ----------------------------------- */
    if (parse_args(argc, argv) < 0) {
	    printf("Argument parsing error!\n" \
	           "Please check your arguments\n");
	    goto out;
    }
    if (args.startup_delay) {
	    unsigned int s;
	    printf("Startup delay");
	    fflush(stdout);
	    for (s = 0; s < args.startup_delay; ++s) {
		    printf(".");
		    fflush(stdout);
		    msleep(1000);
	    }
	    printf("\n");
    }

    /* -----------------------------------
     * lwIP initialization
     * ----------------------------------- */
    printf("Starting networking...\n");
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
        printf("FATAL: Could not initialize the network interface\n");
        goto out;
    }
    netif_set_default(&netif);
    netif_set_up(&netif);
    if (args.dhclient)
        dhcp_start(&netif);

    /* -----------------------------------
     * filesystem automount
     * ----------------------------------- */
    init_shfs();
    printf("Trying to mount cache filesystem...\n");
    ret = mount_shfs(args.vbd_id, args.nb_vbds);
    if (ret < 0)
	    printf("ERROR: Could not mount cache filesystem\n");

    /* -----------------------------------
     * service initialization
     * ----------------------------------- */
    printf("Starting shell...\n");
    init_shell(0, 4); /* no local session + 4 telnet sessions */
    printf("Starting httpd...\n");
    init_httpd();

    /* add custom commands to the shell */
    shell_register_cmd("halt", shcmd_halt);
    shell_register_cmd("reboot", shcmd_reboot);
    shell_register_cmd("suspend", shcmd_suspend);
    shell_register_cmd("lsvbd", shcmd_lsvbd);
    shell_register_cmd("mount", shcmd_mount_shfs);
    shell_register_cmd("umount", shcmd_umount_shfs);
    register_shfs_tools();

    /* -----------------------------------
     * Processing loop
     * ----------------------------------- */
    printf("*** MiniCache is up and running ***\n");
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
	/* Process lwip network-related timers */
        now = NSEC_TO_MSEC(NOW());
        TIMED(now, ts_etharp,  ARP_TMR_INTERVAL, etharp_tmr());
        TIMED(now, ts_ipreass, IP_TMR_INTERVAL,  ip_reass_tmr());
        TIMED(now, ts_tcp,     TCP_TMR_INTERVAL, tcp_tmr());
        TIMED(now, ts_dns,     DNS_TMR_INTERVAL, dns_tmr());
        if (args.dhclient) {
	        TIMED(now, ts_dhcp_fine,   DHCP_FINE_TIMER_MSECS,   dhcp_fine_tmr());
	        TIMED(now, ts_dhcp_coarse, DHCP_COARSE_TIMER_MSECS, dhcp_coarse_tmr());
        }
#endif /* CONFIG_LWIP_SINGLETHREADED */
        schedule(); /* yield CPU */

        if (unlikely(shall_suspend)) {
            printf("System is going to suspend now\n");
            netif_set_down(&netif);
            netif_remove(&netif);

            kernel_suspend();

            printf("System woke up from suspend\n");
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
	    printf("System is going down to reboot now\n");
    else
	    printf("System is going down to halt now\n");
    printf("Stopping httpd...\n");
    exit_httpd();
    printf("Stopping shell...\n");
    exit_shell();
    printf("Unmounting cache filesystem...\n");
    umount_shfs();
    exit_shfs();
    printf("Stopping networking...\n");
    netif_set_down(&netif);
    netif_remove(&netif);
 out:
    if (shall_reboot)
	    kernel_poweroff(SHUTDOWN_reboot);
    kernel_poweroff(SHUTDOWN_poweroff);

    return 0; /* will never be reached */
}
