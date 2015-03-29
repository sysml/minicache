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

#include <lockfree/ring.hh>
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
using pbuf_ring_t = ring_spsc<struct pbuf *,1024>;
/* spsc = single producer, single consumer */

struct _onio {
  struct ifnet *ifn;
  unsigned char hw_addr[ETHER_ADDR_LEN];
  pbuf_ring_t* rxring;

  struct pbuf *(*mk_pbuf)(const unsigned char *, int);
  void (*drop_pbuf)(struct pbuf *);
  void (*rxcb)(struct pbuf *, void *);
  void *rxcb_argp;
};

static inline int onio_pf_hook(
    void *argv, struct mbuf **m, struct ifnet *ifn, int dir, struct inpcb *inp)
{
  struct _onio *dev = (struct _onio *) argv;
  size_t pktlen;
  const unsigned char *pktbuf;
  struct pbuf *p;
  struct ip *ip = NULL;

  printf("Called hook for mbuf %p dir %d (dev %u: %s)\n",
	 *m, dir, ifn->if_index, ifn->if_xname);

  /* --- HACK HACK HACK HACK --- */
  /* THE MOST UGLIEST HACK YOU HAVE EVER SEEN:
   * replace ifn of onio device
   * (since we couldn't detect eth0 on initialization somehow)
   */
  dev->ifn = ifn;
  /* --- HACK HACK HACK HACK --- */

  /* incoming dev is our hooked dev? */
  if (dev->ifn != ifn)
    return 0; /* packet is returned */

  /* --------------------------------------------- */
  /* starting from here we will consume the packet */

  /*
   * We are called at the IP level, therefore the mbuf has already been
   * adjusted to point to the IP header.
   */
  /* revert number convertions in IP header done by BSD stack */
  ip = mtod(*m, struct ip *);
  ip->ip_len = htons(ip->ip_len);
  ip->ip_off = htons(ip->ip_off);

  /* revert pointing mbuf to ethernet frame */
  pktlen = (*m)->m_hdr.mh_len + ETHER_HDR_LEN;
  pktbuf = mtod(*m, const unsigned char *) - ETHER_HDR_LEN;

  /* copy packet buffer to an lwIP buffer, enqueue it to rx ring */
  p = dev->mk_pbuf(pktbuf, pktlen);
  if (!p) {
    /* pbuf could not be allocated: drop */
    return 1;
  }

  if (!dev->rxring->push(p)) {
    /* ring is full: drop */
    dev->drop_pbuf(p);
    return 1;
  }

  printf("Packet consumed (%u bytes at %p)\n", pktlen, pktbuf);
  return 1;
}

onio *open_onio(const char *ifname,
		struct pbuf *(*mk_pbuf)(const unsigned char *, int),
		void (*drop_pbuf)(struct pbuf *),
		void (*rxcb)(struct pbuf *, void *), void *rxcb_argp)
{
  struct ifnet *ifp;
  struct _onio *dev;
  u_short i;

  dev = (struct _onio *) malloc(sizeof(*dev));
  if (!dev)
    goto err_out;

  dev->rxring = new pbuf_ring_t();
  if (!dev->rxring)
    goto err_free_rxring;

  dev->mk_pbuf = mk_pbuf;
  dev->drop_pbuf = drop_pbuf;
  dev->rxcb = rxcb;
  dev->rxcb_argp = rxcb_argp;

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
    goto err_free_rxring;
  }

  if (dev->ifn->if_addr &&
      dev->ifn->if_addrlen &&
      dev->ifn->if_type == IFT_ETHER) {
    memcpy(dev->hw_addr, IF_LLADDR(dev->ifn), ETHER_ADDR_LEN);
  } else {
    printf("open_onio: Device %s does not have a hardware address. Use a hard-coded one.\n", dev->ifn->if_xname);
    /* bzero(dev->hw_addr, ETHER_ADDR_LEN); */
    dev->hw_addr[0]=0x52;
    dev->hw_addr[1]=0x54;
    dev->hw_addr[2]=0x00;
    dev->hw_addr[3]=0x88;
    dev->hw_addr[4]=0x8e;
    dev->hw_addr[5]=0x59;
  }
  printf("open_onio: Hardware address: %02X:%02X:%02X:%02X:%02X:%02X\n",
	 dev->hw_addr[0], dev->hw_addr[1], dev->hw_addr[2],
	 dev->hw_addr[3], dev->hw_addr[4], dev->hw_addr[5]);

  /*
   * Install PF hook
   */
  pfil_add_hook(onio_pf_hook, (void*) dev, PFIL_IN | PFIL_WAITOK,
		&V_inet_pfil_hook);
  printf("open_onio: PF receive hook installed\n");

 out:
  return dev;

 err_free_rxring:
  delete dev->rxring;
 err_free_dev:
  free(dev);
 err_out:
  return NULL;
}

void close_onio(onio *dev)
{
  struct pbuf *p;

  pfil_remove_hook(onio_pf_hook, (void*) dev, PFIL_IN | PFIL_WAITOK,
		   &V_inet_pfil_hook);
  printf("open_onio: PF receive hook removed\n");

  while(dev->rxring->pop(p))
    dev->drop_pbuf(p);
  delete dev->rxring;
  free(dev);
}

void onio_poll(onio *dev)
{
  struct pbuf *p;

  while(dev->rxring->pop(p))
    dev->rxcb(p, dev->rxcb_argp);
}

int onio_transmit(onio *dev, void *buf, size_t len)
{
  struct mbuf *m = NULL;
  int ret;

  printf("onio_transmit: Going to send out %lu bytes on %s\n",
	 len, dev->ifn->if_xname);

  /* allocate mbuf */
  m = m_getjcl(M_NOWAIT, MT_DATA, M_PKTHDR, MCLBYTES); /* 2048 bytes */
  if (!m) {
    printf("onio_transmit: Could not allocate mbuf!\n");
    return -1;
  }

  /* copy data */
  memcpy(mtod(m, void *), buf, len);
  m->M_dat.MH.MH_pkthdr.csum_flags = 0; /* no CHKSUM offload */
  m->M_dat.MH.MH_pkthdr.len = m->m_hdr.mh_len = len;

  /* transmit directly over Ethernet */
  if (dev->ifn->if_addr &&
      dev->ifn->if_addrlen &&
      dev->ifn->if_type == IFT_ETHER) {
    ret = dev->ifn->if_transmit(dev->ifn, m);
  } else {
    printf("onio_transmit: %s is not an Ethernet device. Dropping packet!\n",
	   dev->ifn->if_xname);
    m_free(m);
  }

  return ret;
}

size_t onio_get_hwaddr(onio *dev, void *addr_out, size_t maxlen)
{
  size_t len = maxlen > ETHER_ADDR_LEN ? maxlen : ETHER_ADDR_LEN;
  memcpy(addr_out, dev->hw_addr, len);
  return len;
}
