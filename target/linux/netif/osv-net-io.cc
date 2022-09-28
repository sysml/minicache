/*
 * OSv networking glue for lwIP
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

using namespace std;
/* spsc = single producer, single consumer */
using mbuf_ring_t = ring_spsc<struct mbuf *,1024>;

struct _onio {
  struct ifnet *ifn;
  unsigned char hw_addr[ETHER_ADDR_LEN];
  mbuf_ring_t* rxring;

  struct pbuf *(*mk_pbuf)(const unsigned char *, int);
  void (*rxcb)(struct pbuf *, void *);
  void *rxcb_argp;
};

static inline int onio_pf_hook(
    void *argv, struct mbuf **m, struct ifnet *ifn, int dir, struct inpcb *inp)
{
  struct _onio *dev = (struct _onio *) argv;
  struct mbuf *m2;
  struct ip *ip = NULL;

  //printf("Called hook for mbuf %p dir %d (dev %u: %s)\n",
  //	 *m, dir, ifn->if_index, ifn->if_xname);

  /* incoming dev is our hooked dev? (this is hacky, I know) */
  if (dev->ifn != ifn)
    return 0; /* packet is returned for other pf filters */

  /*
   * We are called at the IP level, therefore the mbuf has already been
   * adjusted to point to the IP header.
   */
  /* revert number convertions in IP header done by BSD stack */
  ip = mtod(*m, struct ip *);
  ip->ip_len = htons(ip->ip_len);
  ip->ip_off = htons(ip->ip_off);

  /* increase refcount of packet and enqueue it */
  m2 = m_copypacket(*m, M_NOWAIT);
  m_freem(*m);
  *m = nullptr;
  if (!m2) {
    /* drop packet */
    return 1;
  }

  if (!dev->rxring->push(m2)) {
    /* drop packet */
    m_freem(m2);
    return 1;
  }

  return 1;
}

onio *open_onio(const char *ifname,
		struct pbuf *(*mk_pbuf)(const unsigned char *, int),
		void (*rxcb)(struct pbuf *, void *), void *rxcb_argp)
{
  struct ifnet *ifp;
  struct _onio *dev;

  dev = (struct _onio *) malloc(sizeof(*dev));
  if (!dev)
    goto err_out;

  dev->rxring = new mbuf_ring_t();
  if (!dev->rxring)
    goto err_free_rxring;

  dev->mk_pbuf = mk_pbuf;
  dev->rxcb = rxcb;
  dev->rxcb_argp = rxcb_argp;

  /*
   * Open IFNET
   */
  /* --- DEBUG --- */
  IFNET_RLOCK();
  TAILQ_FOREACH(ifp, &V_ifnet, if_link) {
    if ( (!(ifp->if_flags & IFF_DYING)) &&
	 (!(ifp->if_flags & IFF_LOOPBACK)) ) {
      printf(" %s\n", ifp->if_xname);
    }
  }
  IFNET_RUNLOCK();
  /* --- DEBUG --- */

  dev->ifn = NULL;
  if (ifname == NULL) {
    /* auto-detect first iface */
    IFNET_RLOCK();
    TAILQ_FOREACH(ifp, &V_ifnet, if_link) {
      if ( (!(ifp->if_flags & IFF_DYING)) &&
	   (!(ifp->if_flags & IFF_LOOPBACK)) ) {
	printf("open_onio: Found and opened ifnet %s\n", ifp->if_xname);
	dev->ifn = ifp;
      }
    }
    IFNET_RUNLOCK();
  } else {
    /* search for iface explicitly */
    IFNET_RLOCK();
    TAILQ_FOREACH(ifp, &V_ifnet, if_link) {
      if ( (!(ifp->if_flags & IFF_DYING)) &&
	   (!(ifp->if_flags & IFF_LOOPBACK)) ) {
	if (strncmp(ifname, dev->ifn->if_xname, IFNAMSIZ)==0) {
	  printf("open_onio: Found and opened ifnet %s\n", ifp->if_xname);
	  dev->ifn = ifp;
	  break;
	}
      }
    }
    IFNET_RUNLOCK();
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
  struct mbuf *m;

  pfil_remove_hook(onio_pf_hook, (void*) dev, PFIL_IN | PFIL_WAITOK,
		   &V_inet_pfil_hook);
  printf("open_onio: PF receive hook removed\n");

  while(dev->rxring->pop(m))
  m_freem(m);
  delete dev->rxring;
  free(dev);
}

void onio_poll(onio *dev)
{
  struct pbuf *p;
  struct mbuf *m;

  size_t pktlen;
  const unsigned char *pktbuf;

  while(dev->rxring->pop(m)) {
    pktlen = m->m_hdr.mh_len;
    pktbuf = mtod(m, const unsigned char *);

    /* copy packet buffer to an lwIP buffer, enqueue it to rx ring */
    p = dev->mk_pbuf(pktbuf, pktlen);
    if (!p) {
      /* pbuf could not be allocated: drop */
      m_freem(m);
      continue;
    }

    dev->rxcb(p, dev->rxcb_argp);
    m_freem(m);
  }
}

int onio_transmit(onio *dev, void *buf, size_t len)
{
  struct bsd_sockaddr dst = { 0 };
  struct bsd_sockaddr_in *dstin = (struct bsd_sockaddr_in *) &dst;
  struct mbuf *m = NULL;
  struct ip *ip = NULL;
  int ret;

  /* allocate mbuf */
  m = m_getjcl(M_NOWAIT, MT_DATA, M_PKTHDR, MCLBYTES); /* 2048 bytes */
  if (!m) {
    printf("onio_transmit: Could not allocate mbuf!\n");
    return -1;
  }

  /* copy payload (incl. IPv4 header) */
  /* TODO: padd ETHER_ADDR_LEN so that a single mbuf is used in the stack
   *       -> mnakes sure that PREPEND will not allocate further memory */
  memcpy(mtod(m, unsigned char *), buf, len);
  m->M_dat.MH.MH_pkthdr.csum_flags = 0; /* no CHKSUM offload */
  m->M_dat.MH.MH_pkthdr.len = m->m_hdr.mh_len = len;

  /* set destination IP on bsd_socketaddr */
  dst.sa_family = AF_INET; /* IPv4 */
  dst.sa_len = 2;
  ip = mtod(m, struct ip *);
  memcpy(&dstin->sin_addr, &ip->ip_dst, sizeof(ip->ip_dst));


  /* transmit IPv4 packet (function will do Ethernet encapsulation and ARP) */
  ret = dev->ifn->if_output(dev->ifn, m, &dst, NULL);
  return ret;
}

size_t onio_get_hwaddr(onio *dev, void *addr_out, size_t maxlen)
{
  size_t len = maxlen > ETHER_ADDR_LEN ? maxlen : ETHER_ADDR_LEN;
  memcpy(addr_out, dev->hw_addr, len);
  return len;
}
