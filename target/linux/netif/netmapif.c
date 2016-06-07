/*
 * NETMAP network driver for lwIP
 *
 *   file: netmapif.c
 *
 *          NEC Europe Ltd. PROPRIETARY INFORMATION
 *
 * This software is supplied under the terms of a license agreement
 * or nondisclosure agreement with NEC Europe Ltd. and may not be
 * copied or disclosed except in accordance with the terms of that
 * agreement. The software and its source code contain valuable trade
 * secrets and confidential information which have to be maintained in
 * confidence.
 * Any unauthorized publication, transfer to third parties or duplication
 * of the object or source code - either totally or in part – is
 * prohibited.
 *
 *      Copyright (c) 2015 NEC Europe Ltd. All Rights Reserved.
 *
 * Authors: Simon Kuenzer <simon.kuenzer@neclab.eu>
 *
 * NEC Europe Ltd. DISCLAIMS ALL WARRANTIES, EITHER EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE AND THE WARRANTY AGAINST LATENT
 * DEFECTS, WITH RESPECT TO THE PROGRAM AND THE ACCOMPANYING
 * DOCUMENTATION.
 *
 * No Liability For Consequential Damages IN NO EVENT SHALL NEC Europe
 * Ltd., NEC Corporation OR ANY OF ITS SUBSIDIARIES BE LIABLE FOR ANY
 * DAMAGES WHATSOEVER (INCLUDING, WITHOUT LIMITATION, DAMAGES FOR LOSS
 * OF BUSINESS PROFITS, BUSINESS INTERRUPTION, LOSS OF INFORMATION, OR
 * OTHER PECUNIARY LOSS AND INDIRECT, CONSEQUENTIAL, INCIDENTAL,
 * ECONOMIC OR PUNITIVE DAMAGES) ARISING OUT OF THE USE OF OR INABILITY
 * TO USE THIS PROGRAM, EVEN IF NEC Europe Ltd. HAS BEEN ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGES.
 *
 *     THIS HEADER MAY NOT BE EXTRACTED OR MODIFIED IN ANY WAY.
 *
 * This file is based on Ethernet Interface skeleton (ethernetif.c)
 * provided by lwIP-1.4.1, copyrights as below.
 */
/*
 * Copyright (c) 2001-2004 Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 *
 * Author: Adam Dunkels <adam@sics.se>
 *
 */
/*
 * Parts of this file are based on the previous lwip-net.c implementation:
 *
 * interface between lwIP's ethernet and Mini-os's netfront.
 * For now, support only one network interface, as mini-os does.
 *
 * Tim Deegan <Tim.Deegan@eu.citrix.net>, July 2007
 * based on lwIP's ethernetif.c skeleton file, copyrights as below.
 */

#include <netif/netmapif.h>
#include <sys/sysctl.h> /* sysctl */

#include <ifaddrs.h>	/* getifaddrs */
#ifdef __linux__
#include <linux/if_packet.h>    /* sockaddr_ll */
#define sockaddr_dl    sockaddr_ll
#define sdl_family     sll_family
#define AF_LINK        AF_PACKET
#define LLADDR(s)      s->sll_addr;
#endif
#ifdef __FreeBSD__
#include <net/if_dl.h>  /* LLADDR */
#endif /* __FreeBSD__ */

#include <stdlib.h>
#include "likely.h"
#include "lwip/def.h"
#include "lwip/mem.h"
#include "lwip/pbuf.h"
#include <lwip/stats.h>
#include <lwip/snmp.h>

#include <hexdump.h>

#define NMNETIF_NPREFIX 'e'
#define NMNETIF_SPEED 0ul     /* 0 for unknown */
#define NMNETIF_MTU 1500

#define NMNETIF_GSO_TYPE_NONE  0x00
#define NMNETIF_GSO_TYPE_UDPV4 0x03
#define NMNETIF_GSO_TYPE_UDPV6 0x05
#define NMNETIF_GSO_TYPE_TCPV4 0x04
#define NMNETIF_GSO_TYPE_TCPV6 0x06

#define NMNETIF_MEMCPY memcpy

/**
 * Helper macros
 */
#ifndef min
#define min(a, b)						\
    ({ __typeof__ (a) __a = (a);				\
       __typeof__ (b) __b = (b);				\
       __a < __b ? __a : __b; })
#endif
#ifndef DIV_ROUND_UP
#define DIV_ROUND_UP(num, div) (((num) + (div) - 1) / (div))
#endif

#define netmapif_count_pbuf_txslots(nmi, p)	\
  DIV_ROUND_UP(((unsigned int)(p)->tot_len), (nmi)->_txring->nr_buf_size);

/**
 * Transmit function for pbufs which can handle checksum and segmentation offloading for TCPv4 and TCPv6
 */
static err_t netmapif_output(struct netmapif *nmi, struct pbuf *p, int co_type, int push)
{
  unsigned int slots;
  struct netmap_slot *slot;
  unsigned int cur;
  uint16_t s_off, s_left;
  void *s_buf;
  uint16_t p_off, p_left;
  unsigned int len;

  LWIP_DEBUGF(NETIF_DEBUG, ("netmapif_output: %p (%zu bytes, gso=%d, %s%d slots)\n", p, p->tot_len, co_type, push ? "push, " : "", slots));

#ifndef CONFIG_NETFRONT_GSO
  slots = netmapif_count_pbuf_txslots(nmi, p);
  if (unlikely(co_type != NMNETIF_GSO_TYPE_NONE)) {
    printf("netmapif_output: FATAL: GSO is not supported");
    return ERR_IF;
  }
#else
  #error "GSO is not supported yet"
#endif

  /* do we have space? */
  if (unlikely(nm_ring_space(nmi->_txring) < slots)) {
    LWIP_DEBUGF(NETIF_DEBUG, ("netmapif_output: not enough slots left on tx ring\n"));
    return ERR_MEM;
  }

  /* copy payload to netmap ring */
  cur    = nmi->_txring->cur;
  slot   = &nmi->_txring->slot[cur];
  cur    = nm_ring_next(nmi->_txring, cur);
  s_buf  = NETMAP_BUF(nmi->_txring, slot->buf_idx);;
  s_off  = 0;
  s_left = nmi->_txring->nr_buf_size;;
  p_off  = 0;
  p_left = p->len;
  for (;;) {
    len = min(s_left, p_left);

    LWIP_DEBUGF(NETIF_DEBUG, ("tx: s@%12p, s_off: %4lu s_left: %4lu <-%4lu bytes-- p@%12p, p_off: %4lu, p_left: %4lu\n",
			       s_buf, s_off, s_left, len, p->payload, p_off, p_left));
    NMNETIF_MEMCPY((void *)(((uintptr_t) s_buf) + s_off),
		   (void *)(((uintptr_t) p->payload) + p_off),
		   len);
    p_off     += len;
    p_left    -= len;
    s_off     += len;
    s_left    -= len;

    if (p_left == 0) {
      if (!p->next)
	break; /* we are done with processing this pbuf chain */
      p = p->next;
      p_off  = 0;
      p_left = p->len;
    }

    if (s_left == 0) {
      /* switch to next netmap slot */
      slot->len   = s_off;
      slot->flags = NS_MOREFRAG;
      slot   = &nmi->_txring->slot[cur];
      cur    = nm_ring_next(nmi->_txring, cur);
      s_buf  = NETMAP_BUF(nmi->_txring, slot->buf_idx);
      s_off  = 0;
      s_left = nmi->_txring->nr_buf_size;
    }
  }
  slot->len   = s_off;
  slot->flags = NS_REPORT;

  nmi->_txring->head = nmi->_txring->cur = cur;

  if (push)
    ioctl(nmi->_fd, NIOCTXSYNC, NULL);
  return ERR_OK;
}

/**
 * This function does the actual transmission of a packet. The packet is
 * contained in the pbuf that is passed to the function. This pbuf
 * can be chained.
 *
 * @param netif
 *  the lwip network interface structure for this netmapif
 * @param p
 *  the packet to send (e.g. IP packet including MAC addresses and type)
 * @return
 *  ERR_OK when the packet could be sent; an err_t value otherwise
 */
static err_t netmapif_transmit(struct netif *netif, struct pbuf *p)
{
    struct netmapif *nmi = netif->state;
#if defined CONFIG_NETFRONT_GSO || defined CONFIG_LWIP_BATCHTX
    s16_t ip_hdr_offset;
    const struct eth_hdr *ethhdr;
    const struct ip_hdr *iphdr;
#endif /* defined CONFIG_NETFRONT_GSO || defined CONFIG_LWIP_BATCHTX */
#ifdef CONFIG_LWIP_BATCHTX
    const struct tcp_hdr *tcphdr;
#endif /* CONFIG_LWIP_BATCHTX */
    int tso = 0;
    int push = 1;
    err_t err;

    LWIP_DEBUGF(NETIF_DEBUG, ("netmapif_transmit: %c%c: "
			      "Transmitting %u bytes\n",
			      netif->name[0], netif->name[1],
			      p->tot_len));

#if defined CONFIG_NETFRONT_GSO || defined CONFIG_LWIP_BATCHTX
    /* detect if payload contains a TCP packet */
    /* NOTE: We assume here that all protocol headers are in the first pbuf of a pbuf chain! */
    ip_hdr_offset = SIZEOF_ETH_HDR;
    ethhdr = (struct eth_hdr *) p->payload;
#if ETHARP_SUPPORT_VLAN
    if (type == PP_HTONS(ETHTYPE_VLAN)) {
      type = ((struct eth_vlan_hdr*)(((uintptr_t)ethhdr) + SIZEOF_ETH_HDR))->tpid;
      ip_hdr_offset = SIZEOF_ETH_HDR + SIZEOF_VLAN_HDR;
    }
#endif /* ETHARP_SUPPORT_VLAN */
    /* TODO: PPP support? */

    switch (ethhdr->type) {
    case PP_HTONS(ETHTYPE_IP):
      iphdr = (struct ip_hdr *)((uintptr_t) p->payload + ip_hdr_offset);
      if (IPH_PROTO(iphdr) != IP_PROTO_TCP) {
	goto xmit; /* IPv4 but not TCP */
      }
#ifdef CONFIG_NETFRONT_GSO
      tso = NMNETIF_GSO_TYPE_TCPV4; /* TCPv4 segmentation and checksum offloading */
#endif /* CONFIG_NETFRONT_GSO */
#ifdef CONFIG_LWIP_BATCHTX
      /* push only when FIN, RST, PSH, or URG flag is set */
      tcphdr = (struct tcp_hdr *)((uintptr_t) p->payload + ip_hdr_offset + (IPH_HL(iphdr) * 4));
      push = (TCPH_FLAGS(tcphdr) & (TCP_FIN | TCP_RST | TCP_PSH | TCP_URG));
#endif /* CONFIG_LWIP_BATCHTX */
      break;

#if IPV6_SUPPORT
    case PP_HTONS(ETHTYPE_IPV6):
      if (IP6H_NEXTH((struct ip6_hdr *)((uintptr_t) p->payload + ip_hdr_offset)) != IP6_NEXTH_TCP)
	goto xmit; /* IPv6 but not TCP */
#ifdef CONFIG_NETFRONT_GSO
      tso = NMNETIF_GSO_TYPE_TCPV6; /* TCPv6 segmentation and checksum offloading */
#endif /* CONFIG_NETFRONT_GSO */
#ifdef CONFIG_LWIP_BATCHTX
      /* push only when FIN, RST, PSH, or URG flag is set */
      #error "TSOv6 is not yet supported. Please add it"
      tcphdr = NULL;
      push = (TCPH_FLAGS(tcphdr) & (TCP_FIN | TCP_RST | TCP_PSH | TCP_URG));
#endif /* CONFIG_LWIP_BATCHTX */
      break;
#endif /* IPV6_SUPPORT */

    default:
      break; /* non-IP packet */
    }
#endif /* defined CONFIG_NETFRONT_GSO || defined CONFIG_LWIP_BATCHTX */

 xmit:
#if ETH_PAD_SIZE
    pbuf_header(p, -ETH_PAD_SIZE); /* drop the padding word */
#endif
    err = netmapif_output(nmi, p, tso, push);
    if (likely(err == ERR_OK)) {
      LINK_STATS_INC(link.xmit);
    } else {
      LWIP_DEBUGF(NETIF_DEBUG, ("netmapif_transmit: transmission failed, dropping packet: %d\n", err));
      LINK_STATS_INC(link.drop);
    }

#if ETH_PAD_SIZE
    pbuf_header(p, ETH_PAD_SIZE); /* reclaim the padding word */
#endif

    return err;
}

/**
 * Passes a pbuf to the lwIP stack for further processing.
 * The packet type is determined and checked before passing.
 * Note: When lwIP is built with threading, this pbuf will
 * be enqueued to lwIP's mailbox until it gets processed
 * by the tcpip thread.
 *
 * @param p
 *  the pointer to received packet data
 * @param netif
 *  the lwip network interface structure for this netmapif
 */
static inline void netmapif_input(struct pbuf *p, struct netif *netif)
{
    struct eth_hdr *ethhdr;
    err_t err;

    LWIP_DEBUGF(NETIF_DEBUG, ("netmapif_input: %c%c: "
			      "Received %u bytes\n",
			      netif->name[0], netif->name[1],
			      p->tot_len));

    ethhdr = p->payload;
    switch (ethhdr->type) {
    /* IP or ARP packet? */
    case PP_HTONS(ETHTYPE_IP):
#if IPV6_SUPPORT
    case PP_HTONS(ETHTYPE_IPV6):
#endif
    case PP_HTONS(ETHTYPE_ARP):
#if PPPOE_SUPPORT
    case PP_HTONS(ETHTYPE_PPPOEDISC):
    case PP_HTONS(ETHTYPE_PPPOE):
#endif
    /* packet will be sent to lwIP stack for processing */
    /* Note: On threaded configuration packet buffer will be enqueued on
     *  a mailbox. The lwIP thread will do the packet processing when it gets
     *  scheduled. */
        err = netif->input(p, netif);
	if (unlikely(err != ERR_OK)) {
#ifndef CONFIG_LWIP_NOTHREADS
	    if (err == ERR_MEM)
	        LWIP_DEBUGF(NETIF_DEBUG, ("netmapif_input: %c%c: ERROR %d: "
					  "Could not post packet to lwIP thread. Packet dropped\n",
					  netif->name[0], netif->name[1], err));
	    else
#endif /* CONFIG_LWIP_NOTHREADS */
	    LWIP_DEBUGF(NETIF_DEBUG, ("netmapif_input: %c%c: ERROR %d: "
				      "Packet dropped\n",
				      netif->name[0], netif->name[1], err));
	    pbuf_free(p);
	}
	break;

    default:
        LWIP_DEBUGF(NETIF_DEBUG, ("netmapif_input: %c%c: ERROR: "
				  "Dropped packet with unknown type 0x%04x\n",
				  netif->name[0], netif->name[1],
				  htons(ethhdr->type)));
	pbuf_free(p);
	break;
    }
}

/*
 * Returns number of bytes and segments of a received packet
 */
static inline uint16_t
netmapif_get_rxlen(struct netmap_ring *rxring, unsigned int cur,
		   unsigned int *next, unsigned int *out_nbslots)
{
	uint16_t nb_slots = 0;
	uint16_t rxlen = 0;
	struct netmap_slot *slot;

	for (;;) {
		slot   = &rxring->slot[cur];
		rxlen += slot->len;
		++nb_slots;
		cur    = nm_ring_next(rxring, cur);
	        if (!(slot->flags & NS_MOREFRAG))
			break;
	}
	if (next)
	  *next = cur;
	if (out_nbslots)
	  *out_nbslots = nb_slots;
	return rxlen;
}

/* copies netmap slots into a pre-allocated pbuf chain */
static inline void
netmapif_receive(struct netmap_ring *rxring, unsigned int cur, struct pbuf *p)
{
	unsigned int slots;
	struct netmap_slot *slot;
	uint16_t s_off, s_left;
	void *s_buf;
	uint16_t p_off, p_left;
	unsigned int len;

	/* copy payload from netmap ring */
	cur    = rxring->cur;
	slot   = &rxring->slot[cur];
	cur    = nm_ring_next(rxring, cur);
	s_buf  = NETMAP_BUF(rxring, slot->buf_idx);;
	s_off  = 0;
	s_left = slot->len;
	p_off  = 0;
	p_left = p->len;
	for (;;) {
	  len = min(s_left, p_left);

	  LWIP_DEBUGF(NETIF_DEBUG, ("rx: s@%12p, s_off: %4lu s_left: %4lu --%4lu bytes-> p@%12p, p_off: %4lu, p_left: %4lu\n",
				    s_buf, s_off, s_left, len, p->payload, p_off, p_left));
	  NMNETIF_MEMCPY((void *)(((uintptr_t) p->payload) + p_off),
			 (void *)(((uintptr_t) s_buf) + s_off),
			 len);
	  p_off     += len;
	  p_left    -= len;
	  s_off     += len;
	  s_left    -= len;

	  if (s_left == 0) {
	    if (!(slot->flags & NS_MOREFRAG))
	      break; /* we are done */

	    /* switch to next netmap slot */
	    slot   = &rxring->slot[cur];
	    cur    = nm_ring_next(rxring, cur);
	    s_buf  = NETMAP_BUF(rxring, slot->buf_idx);
	    s_off  = 0;
	    s_left = slot->len;
	  }

	  if (p_left == 0) {
	    p = p->next;
	    BUG_ON(!p); /* only happens if pbuf is smaller than received data */
	    p_off  = 0;
	    p_left = p->len;
	  }

	}
}
/*
 * Receive packets from netmap ring and send them to
 * netmapif_input()
 */
void netmapif_poll(struct netif *netif)
{
  struct netmapif *nmi = netif->state;
  unsigned int slots, tot_slots;
  unsigned int cur, next, pkg_len;
  struct pbuf *p;

  /* call receive ioctl (TODO: expose filedescriptor to do rx select/poll outside of this function) */
  ioctl(nmi->_fd, NIOCRXSYNC, NULL);

  /* handle received packets */
  tot_slots = nm_ring_space(nmi->_rxring);
  cur = nmi->_rxring->cur;
  while (tot_slots) {
    pkg_len = netmapif_get_rxlen(nmi->_rxring, cur, &next, &slots);
    LWIP_DEBUGF(NETIF_DEBUG, ("netmapif_poll: %c%c: "
			      "incoming data %u bytes, %u slots\n",
			      netif->name[0], netif->name[1],
			      pkg_len, slots));

    if (unlikely((pkg_len) > 0xFFFF - ETH_PAD_SIZE))  {
      LWIP_DEBUGF(NETIF_DEBUG, ("netmapif_poll: %c%c: "
				"could not receive packet: too big!?\n",
				netif->name[0], netif->name[1]));
      p = NULL;
    } else {
      p = pbuf_alloc(PBUF_RAW, (u16_t) (pkg_len + ETH_PAD_SIZE), PBUF_POOL);
      if (unlikely(!p)) {
	LWIP_DEBUGF(NETIF_DEBUG, ("netmapif_poll: %c%c: "
				  "could not allocate pbuf, dropping packet\n",
				  netif->name[0], netif->name[1]));
      } else {
	/* copy received data into pbuf */
#if ETH_PAD_SIZE
	pbuf_header(p, -ETH_PAD_SIZE); /* drop the padding word */
#endif /* ETH_PAD_SIZE */
	netmapif_receive(nmi->_rxring, cur, p);
#if ETH_PAD_SIZE
	pbuf_header(p, ETH_PAD_SIZE); /* reclaim the padding word */
#endif /* ETH_PAD_SIZE */
      }
    }
    netmapif_input(p, netif);
    cur = next;
    tot_slots -= slots;
  }

  nmi->_rxring->head = nmi->_rxring->cur = cur;
}

#ifndef CONFIG_LWIP_NOTHREADS
/**
 * Network polling thread function
 *
 * @param argp
 *  pointer to netif
 */
/* TODO: Use mini-os's blocking poll */
static void netmapif_thread(void *argp)
{
    struct netif *netif = argp;
    struct netmapif *nmi = netif->state;
    onio *dev = nmi->dev;

    while (likely(!nmi->_thread_exit)) {
        netmapif_poll(dev);
        schedule();
    }

    nmi->_thread_exit = 0;
}
#endif /* CONFIG_LWIP_NOTHREADS */

#if LWIP_NETIF_REMOVE_CALLBACK
/**
 * Closes a network interface.
 * This function is called by lwIP on netif_remove().
 *
 * @param netif
 *  the lwip network interface structure for this netmapif
 */
static void netmapif_exit(struct netif *netif)
{
    struct netmapif *nmi = netif->state;

    nm_close(nmi->dev);

#ifndef CONFIG_LWIP_NOTHREADS
    LWIP_DEBUGF(NETIF_DEBUG, ("netmapif_exit: wait for thread shutdown\n"));
    nmi->_thread_exit = 1; /* request exit */
    while (nmi->_thread_exit)
        schedule();
    LWIP_DEBUGF(NETIF_DEBUG, ("netmapif_exit: thread was shutdown\n"));
#endif /* CONFIG_LWIP_NOTHREADS */

    if (nmi->_state_is_private) {
	mem_free(nmi);
	netif->state = NULL;
    }
}
#endif /* LWIP_NETIF_REMOVE_CALLBACK */

/* Returns 0 on success and puts the hwaddress of an interface on addr_out
 *  on errors, -1 is returned
 * Note: adopted from examples/pkt-gen.c */
static int
_sys_get_hwaddr(const char *ifname,
		struct eth_addr *out)
{
	struct ifaddrs *ifap_head, *ifap;
	struct sockaddr_dl *saddr_dl;
	size_t max_ifname_len;
	uint8_t *hwaddr;
	unsigned i;
	int ret = 0;

	if (getifaddrs(&ifap_head) != 0) {
		ret = -1;
		goto out;
	}

	max_ifname_len = sizeof(ifap->ifa_name);
	hwaddr = NULL;
	for (ifap = ifap_head; ifap != NULL; ifap = ifap->ifa_next) {
		saddr_dl = (struct sockaddr_dl *) ifap->ifa_addr;

		if (!saddr_dl || saddr_dl->sdl_family != AF_LINK)
			continue;
		if (strncmp(ifap->ifa_name, ifname, max_ifname_len) != 0)
			continue;

		hwaddr = (uint8_t *) LLADDR(saddr_dl);
		break;
	}

	if (!hwaddr) {
		ret = -1;
		goto out_free_ifap;
	}
	for (i = 0; i < ETHARP_HWADDR_LEN; ++i)
		out->addr[i] = hwaddr[i];

 out_free_ifap:
	freeifaddrs(ifap_head);
 out:
	return ret;
}

/* generate a private hardware address
 *  x2-xx-xx-xx-xx-xx
 *  x6-xx-xx-xx-xx-xx
 *  xA-xx-xx-xx-xx-xx
 *  xE-xx-xx-xx-xx-xx
 * x := 0-F except for the first position (0-E)
 */
static void
_sys_gen_hwaddr(struct eth_addr *out)
{
  unsigned int i;
  /* generate random bytes */
  for (i = 0; i < ETHARP_HWADDR_LEN; ++i)
    out->addr[i] = (u8_t) rand();

  /* modify first byte (make hwaddr private) */
  out->addr[0] &= (out->addr[0] >= 0xF0) ? 0xEC : 0xFC;
  out->addr[0] |= 0x02;
}

/**
 * Initializes and sets up a netfront interface for lwIP.
 * This function should be passed as a parameter to netmapif_add().
 *
 * @param netif
 *  the lwip network interface structure for this netmapif
 * @return
 *  ERR_OK if the interface was successfully initialized;
 *  An err_t value otherwise
 */
err_t netmapif_init(struct netif *netif)
{
    struct netmapif *nmi;
    static uint8_t netmapif_id = 0;

    LWIP_ASSERT("netif != NULL", (netif != NULL));

    if (!(netif->state)) {
	nmi = mem_calloc(1, sizeof(*nmi));
	if (!nmi) {
	    LWIP_DEBUGF(NETIF_DEBUG, ("netmapif_init: "
				      "Could not allocate \n"));
	    goto err_out;
	}
	netif->state = nmi;
	nmi->_state_is_private = 1;
	nmi->_dev_is_private = 1;
	nmi->_hwaddr_is_private = 1;
    } else {
	nmi = netif->state;
	nmi->_state_is_private = 0;
	nmi->_dev_is_private = !(nmi->dev);
	nmi->_hwaddr_is_private = eth_addr_cmp(&nmi->hwaddr, &ethzero);
    }

    /* Netmap */
    if (nmi->_dev_is_private) {
        /* user did not provide an opened netfront, we need to do it here */
	if (nmi->_state_is_private) {
	  /* open eth2 interface as default */
	  snprintf(nmi->ifname, sizeof(nmi->ifname), "netmap:eth2/x");
	}

	/* use nmi->ifname to open a specific NIC interface */
	nmi->dev = nm_open(nmi->ifname, NULL, 0 , NULL);
	if (!nmi->dev) {
	    LWIP_DEBUGF(NETIF_DEBUG, ("netmapif_init: "
				      "Could not open %s\n", nmi->ifname));
	    goto err_free_nmi;
	}
    }
    nmi->_nifp = nmi->dev->nifp;

    /* unlikely that this fails, nm_open() should have checked the parameters (hopefully) */
    if (nmi->dev->req.nr_rx_rings < nmi->dev->first_rx_ring ||
	nmi->dev->req.nr_tx_rings < nmi->dev->first_tx_ring) {
      LWIP_DEBUGF(NETIF_DEBUG, ("netmapif_init: "
				"Could not map rings for %s: rx/tx ring index out of range\n", nmi->ifname));
      goto err_close_dev;
    }

    nmi->_fd   = NETMAP_FD(nmi->dev);
    nmi->_rxring = NETMAP_RXRING(nmi->_nifp, nmi->dev->first_rx_ring);
    LWIP_DEBUGF(NETIF_DEBUG, ("netmapif_init: %s: use rx ring %u\n", nmi->ifname, nmi->dev->first_rx_ring));
    nmi->_txring = NETMAP_TXRING(nmi->_nifp, nmi->dev->first_tx_ring);
    LWIP_DEBUGF(NETIF_DEBUG, ("netmapif_init: %s: use tx ring %u\n", nmi->ifname, nmi->dev->first_tx_ring));

    /* Interface identifier */
    netif->name[0] = NMNETIF_NPREFIX;
    netif->name[1] = '0' + netmapif_id;
    netmapif_id++;

    /* MAC address */
    if (nmi->_hwaddr_is_private) {
      if (_sys_get_hwaddr(nmi->dev->req.nr_name, &nmi->hwaddr) < 0) {
	LWIP_DEBUGF(NETIF_DEBUG, ("netmapif_init: %c%c: failed to retrieve hardware address. Generating a random one\n",
				  netif->name[0], netif->name[1]));
	_sys_gen_hwaddr(&nmi->hwaddr);
      }
    }
    LWIP_DEBUGF(NETIF_DEBUG, ("netmapif_init: %c%c: Hardware address: %02x:%02x:%02x:%02x:%02x:%02x\n",
			      netif->name[0], netif->name[1],
			      nmi->hwaddr.addr[0], nmi->hwaddr.addr[1], nmi->hwaddr.addr[2],
			      nmi->hwaddr.addr[3], nmi->hwaddr.addr[4], nmi->hwaddr.addr[5]));
    SMEMCPY(&netif->hwaddr, &nmi->hwaddr, ETHARP_HWADDR_LEN);
    netif->hwaddr_len = ETHARP_HWADDR_LEN;

    /* We directly use etharp_output() here to save a function call.
     * Instead, there could be function declared that calls etharp_output()
     * only if there is a link is available... */
    netif->output = etharp_output;
    netif->linkoutput = netmapif_transmit;
#if LWIP_NETIF_REMOVE_CALLBACK
    netif->remove_callback = netmapif_exit;
#endif /* CONFIG_NETIF_REMOVE_CALLBACK */

    /* Initialize the snmp variables and counters inside the struct netif.
     * The last argument is the link speed, in units of bits per second. */
    NETIF_INIT_SNMP(netif, snmp_ifType_ppp, NMNETIF_SPEED);
    LWIP_DEBUGF(NETIF_DEBUG, ("netmapif_init: %c%c: Link speed: %llu bps\n",
			      netif->name[0], netif->name[1], NMNETIF_SPEED));

    /* Device capabilities */
    netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_LINK_UP;

    /* Maximum transfer unit */
    netif->mtu = NMNETIF_MTU;
    LWIP_DEBUGF(NETIF_DEBUG, ("netmapif_init: %c%c: MTU: %u\n",
			      netif->name[0], netif->name[1], netif->mtu));

#if LWIP_NETIF_HOSTNAME
    /* Initialize interface hostname */
    if (!netif->hostname)
	netif->hostname = NULL;
#endif /* LWIP_NETIF_HOSTNAME */

#ifndef CONFIG_LWIP_NOTHREADS
  nmi->_thread_exit = 0;
  nmi->_thread_name[0] = netif->name[0];
  nmi->_thread_name[1] = netif->name[1];
  nmi->_thread_name[2] = '-';
  nmi->_thread_name[3] = 'r';
  nmi->_thread_name[4] = 'x';
  nmi->_thread_name[5] = '\0';
  create_thread(nmi->_thread_name, netmapif_thread, netif);
#endif /* CONFIG_LWIP_NOTHREADS */

    return ERR_OK;

 err_close_dev:
    nm_close(nmi->dev);
 err_free_nmi:
    if (nmi->_state_is_private) {
	mem_free(nmi);
	netif->state = NULL;
    }
 err_out:
    return ERR_IF;
}
