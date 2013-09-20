/*
 * Simple packet buffer implementation for MiniOS
 *  (based on simple mempool)
 * Copyright(C) 2013 NEC Laboratories Europe. All rights reserved.
 */
#include <mini-os/os.h>
#include <mini-os/types.h>
#include <mini-os/xmalloc.h>
#include <kernel.h>
#include <errno.h>

#include "pktbuf.h"

#define IPV4_VERSION 4

void _pktpool_obj_init(struct mempool_obj *obj, void *argp)
{
  struct pktbuf *pb = (struct pktbuf *) obj;

  pb->next = NULL;
  pb->pktlen = 0;
}

/**
 * Generates an Ethernet-IPv4-UDP packet header on the memory buffer pointed by buf
 *
 *  @buf: Pointer to target memory buffer
 *  @buflen: Length of target buffer
 *  @payload_len: Length of data payload
 *  @src_mac: Source MAC address
 *  @dst_mac: Destination MAC address
 *  @src_ip: Source IPv4 address in the IPv4 header
 *  @dst_ip: Destination IPv4 address in the IPv4 header
 *  @src_port: Source UDP Port
 *  @dst_port: Destination UDP Port
 *  @ttl: Time-To-Live value in IPv4 header
 */
void _pktbuf_do_encap_udp(void *buf, size_t buflen, size_t payload_len,
						  const struct eth_addr *src_mac, const struct eth_addr *dst_mac,
						  const struct ip_addr *src_ip, const struct ip_addr *dst_ip,
						  uint16_t src_port, uint16_t dst_port,
						  uint8_t ttl, int calc_payload_chksum)
{
  size_t hdr_len;

  struct eth_hdr *eh = buf;
  struct ip_hdr *ip = (void *)((uintptr_t) eh + sizeof(*eh));
  struct udp_hdr *udp = (void *)((uintptr_t) ip + sizeof(*ip));
  hdr_len = sizeof(*eh) + sizeof(*ip) + sizeof(*udp);

  ASSERT(buflen >= hdr_len + payload_len); /* buffer is too small */
  ASSERT(payload_len <= UINT16_MAX); /* maximum length */

  /* Ethernet header */
  memcpy(&(eh->src.addr), &(src_mac->addr), ETHARP_HWADDR_LEN);
  memcpy(&(eh->dest.addr), &(dst_mac->addr), ETHARP_HWADDR_LEN);
  eh->type = htons(ETHTYPE_IP);

  /* IPv4 header */
  IPH_VHLTOS_SET(ip, IPV4_VERSION, 5, IPTOS_LOWDELAY);
  ip->_id = 0;
  ip->_len = ntohs(hdr_len + payload_len - sizeof(*eh));
  ip->_id = 0;
  ip->_offset = htons(IP_DF); /* Don't fragment */
  IPH_TTL_SET(ip, ttl);
  IPH_PROTO_SET(ip, IP_PROTO_UDP);
  memcpy(&(ip->src), &(src_ip->addr), sizeof(ip->src));
  memcpy(&(ip->dest), &(dst_ip->addr), sizeof(ip->dest));
  ip->_chksum = 0x0;
  ip->_chksum = wrapsum(checksum(ip, sizeof(*ip), 0));

  udp->src = htons(src_port);
  udp->dest = htons(dst_port);
  udp->len = htons(payload_len + sizeof(*udp));

  if (calc_payload_chksum) {
	/* Magic: taken from sbin/dhclient/packet.c */
	udp->chksum = wrapsum(checksum(udp, sizeof(*udp),
								   checksum((void *)((uintptr_t) buf + hdr_len),
											payload_len,
											checksum(&ip->src, 2 * sizeof(ip->src),
													 IPPROTO_UDP + (uint32_t)ntohs(udp->len)
													 )
											)
								   )
						  );
  } else {
	udp->chksum = 0; /* no UDP checksum */
  }
}
