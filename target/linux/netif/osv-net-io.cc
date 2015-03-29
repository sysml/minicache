/*
 * C++/C wrapper for OSv networking
 */
#include <netif/osv-net-io.h>

#include <features.h>
#include <string>
#include <iostream>
#include <stdio.h>
#include <functional>
#include <sys/cdefs.h>
#include <sys/types.h>
#include <osv/types.h>

//#include <osv/debug.hh>
//#include <osv/clock.hh>
//#include <osv/ilog2.hh>
//#include <osv/mempool.hh>

#include <bsd/porting/netport.h>
#include <bsd/sys/net/if_var.h>
#include <bsd/sys/net/if_dl.h>
#include <bsd/sys/net/if.h>
#include <bsd/sys/sys/mbuf.h>
#include <bsd/sys/net/ethernet.h>
#include <bsd/sys/net/if_types.h>
#include <bsd/sys/sys/param.h>
#include <bsd/sys/net/ethernet.h>
#include <bsd/sys/netinet/in.h>
#include <bsd/sys/netinet/ip.h>
#include <bsd/sys/netinet/udp.h>
#include <bsd/sys/netinet/tcp.h>
#include <bsd/sys/netinet/ip_var.h>
#include <bsd/sys/netinet/udp_var.h>
#include <bsd/sys/net/pfil.h>

//namespace oc = osv::clock;
using namespace std;

struct _onio {
  struct ifnet *ifn;
  char hw_addr[ETHER_ADDR_LEN];
  void (*rxcb)(void *, int, void *);
};

static inline int onio_pf_hook(
    void *argv, struct mbuf **m, struct ifnet *ifn, int dir, struct inpcb *inp)
{
  struct _onio *dev = (struct _onio *) argv;
  printf("Called hook for mbuf %p dir %d\n", *m, dir);

  bool res = 1; //memcached->filter(ifn, *m);
  return (!res) ? 0 : 1;
}

onio *open_onio(const char *ifname, void (*rxcb)(void *, int, void *), void *rxcb_arg)
{
  struct ifnet *ifp;
  struct _onio *dev;
  u_short i;

  dev = (struct _onio *) malloc(sizeof(*dev));
  if (!dev)
    goto err_out;

  /*
   * Open IFNET
   */
  /* --- DEBUG --- */
  for (i=0; i<V_if_index; ++i) {
    ifp = ifnet_byindex_ref(i);
    if (ifp) {
      printf(" %u: %s\n", i, ifp->if_xname);
    }
  }
  /* --- DEBUG --- */

  dev->ifn = NULL;
  if (ifname == NULL) {
    /* auto-detect first iface */
    for (i=0; i<V_if_index; ++i) {
      ifp = ifnet_byindex_ref(i);
      if (ifp) {
	printf("open_onio: Found and opened ifnet at index %u: %s\n", i, ifp->if_xname);
	dev->ifn = ifp;
      }
    }
  } else {
    /* search for iface explicitly */
    for (i=0; i<V_if_index; ++i) {
      ifp = ifnet_byindex_ref(i);
      if (ifp) {
	if (strncmp(ifname, dev->ifn->if_xname, IFNAMSIZ)==0) {
	  printf("open_onio: Found and opened ifnet at index %u: %s\n", i, ifp->if_xname);
	  dev->ifn = ifp;
	  break;
	}
      }
    }
  }
  if (!dev->ifn) {
    printf("open_onio: Could not find device %s\n", ifname ? ifname : "");
    goto err_free_dev;
  }

  if (dev->ifn->if_addr &&
      dev->ifn->if_addrlen &&
      dev->ifn->if_type == IFT_ETHER) {
    memcpy(dev->hw_addr, IF_LLADDR(dev->ifn), ETHER_ADDR_LEN);
    printf("open_onio: Hardware address: %02X:%02X:%02X:%02X:%02X:%02X\n",
	   dev->hw_addr[0], dev->hw_addr[1], dev->hw_addr[2],
	   dev->hw_addr[3], dev->hw_addr[4], dev->hw_addr[5]);
  } else {
    printf("open_onio: Device %s does not have an hardware address\n", dev->ifn->if_xname);
    bzero(dev->hw_addr, ETHER_ADDR_LEN);
  }
  dev->rxcb = rxcb;

  /*
   * Install PF hook
   */
  pfil_add_hook(onio_pf_hook, (void*) dev, PFIL_IN | PFIL_WAITOK,
		&V_inet_pfil_hook);
  printf("open_onio: PF receive hook installed\n");

 out:
  return dev;

 err_free_dev:
  free(dev);
 err_out:
  return NULL;
}

void close_onio(onio *dev)
{
  free(dev);
}

void onio_poll(onio *dev)
{
  return;
}

int onio_transmit(onio *dev, void *pkt, size_t len)
{
  return -1;
}

size_t onio_get_hwaddr(onio *dev, void *addr_out, size_t maxlen)
{
  size_t len = maxlen > ETHER_ADDR_LEN ? maxlen : ETHER_ADDR_LEN;
  memcpy(addr_out, dev->hw_addr, len);
  return len;
}
