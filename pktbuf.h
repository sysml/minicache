/*
 * Simple packet buffer implementation for MiniOS
 *  (based on simple mempool)
 * Copyright(C) 2013 NEC Laboratories Europe. All rights reserved.
 */
#ifndef _PKTBUF_H_
#define _PKTBUF_H_

#include <netif/etharp.h>
#include <lwip/ip_addr.h>
#include <lwip/udp.h>
#include <lwip/sockets.h>
#include "mempool.h"

struct pktbuf {
  struct mempool_obj p_obj; /* surrounding memory pool object (NOTE: has to be the first element of this struct for simple type casting) */

  struct pktbuf *next; /* packet buffer chaining */
  size_t pktlen;
  void *private; /* user definable value */
};

void _pktpool_obj_init(struct mempool_obj *obj, void *argp);

#define alloc_pktpool(nb_pkts, max_pktlen, pktbuf_align, pktbuf_headroom, pktbuf_tailroom) \
  alloc_mempool((nb_pkts), (max_pktlen), (pktbuf_align), (pktbuf_headroom), (pktbuf_tailroom), _pktpool_obj_init, NULL, (sizeof(struct pktbuf) - sizeof(struct mempool_obj)))
#define alloc_simple_pktpool(nb_pkts, max_pktlen) \
  alloc_simple_mempool((nb_pkts), (max_pktlen), 0, 0, 0, _pktpool_obj_init, NULL, (sizeof(struct pktbuf) - sizeof(struct mempool_obj)))
#define free_pktpool(p) \
  free_mempool((p))
#define pktpool_pick(p) \
  ((struct pktbuf *) mempool_pick((p)))
#define pktpool_pick_multiple(p, pkts, count) \
  mempool_pick_multiple((p), (struct mempool_obj **) (pkts), (count))
#define pktpool_put(pkt) \
  mempool_put((struct mempool_obj *) (pkt))
#define pktpool_put_multiple(pkt, count) \
  mempool_put_multiple((struct mempool_obj **) (pkt), (count))  /* packets need to be allocated from the same pktpool */
#define pktpool_free_count(p) \
  mempool_free_count((struct mempool *) (p))

static inline int pktbuf_prepend(struct pktbuf *pkt, size_t len)
{
  int ret;
  ret = mempool_obj_prepend((struct mempool_obj *) pkt, len);
  if (ret < 0)
	return ret;

  pkt->pktlen += len;
  return ret;
}

static inline void pktbuf_prepend_nocheck(struct pktbuf *pkt, size_t len)
{
  mempool_obj_prepend_nocheck((struct mempool_obj *) pkt, len);
  pkt->pktlen += len;
}

#define pktbuf_append(pkt, len) \
  mempool_obj_append((struct mempool_obj *)(pkt), (len))
#define pktbuf_append_nocheck(pkt, len) \
  mempool_obj_append_nocheck((struct mempool_obj *)(pkt), (len))

void _pktbuf_do_encap_udp(void *buf, size_t buflen, size_t payload_len,
						  const struct eth_addr *src_mac, const struct eth_addr *dst_mac,
						  const struct ip_addr *src_ip, const struct ip_addr *dst_ip,
						  uint16_t src_port, uint16_t dst_port,
						  uint8_t ttl, int calc_payload_chksum);

static inline int pktbuf_encap_udp(struct pktbuf *pkt, const struct eth_addr *src_mac, const struct eth_addr *dst_mac,
								   const struct ip_addr *src_ip, const struct ip_addr *dst_ip,
								   uint16_t src_port, uint16_t dst_port,
								   uint8_t ttl, int calc_payload_chksum)
{
  int ret;
  size_t pktlen;

  pktlen = pkt->pktlen;
  ret = pktbuf_prepend(pkt, sizeof(struct eth_hdr) + sizeof(struct ip_hdr) + sizeof(struct udp_hdr));
  if (unlikely(ret))
	return ret;
  _pktbuf_do_encap_udp(pkt->p_obj.data, pkt->p_obj.len, pktlen, src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, ttl, calc_payload_chksum);
  return 0;
}

static inline void pktbuf_encap_udp_nocheck(struct pktbuf *pkt, const struct eth_addr *src_mac, const struct eth_addr *dst_mac,
											const struct ip_addr *src_ip, const struct ip_addr *dst_ip,
											uint16_t src_port, uint16_t dst_port,
											uint8_t ttl, int calc_payload_chksum)
{
  size_t pktlen = pkt->pktlen;
  pktbuf_prepend_nocheck(pkt, sizeof(struct eth_hdr) + sizeof(struct ip_hdr) + sizeof(struct udp_hdr));
  _pktbuf_do_encap_udp(pkt->p_obj.data, pkt->p_obj.len, pktlen, src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, ttl, calc_payload_chksum);
}

/*
 * The following code was copied from pkt-gen
 */
/* Compute the checksum of the given ip header. */
static inline uint16_t checksum(const void *data, uint16_t len, uint32_t sum)
{
  const uint8_t *addr = data;
  uint32_t i;

  /* Checksum all the pairs of bytes first... */
  for (i = 0; i < (len & ~1U); i += 2) {
	sum += (uint16_t)ntohs(*((uint16_t *)(addr + i)));
	if (sum > 0xFFFF)
	  sum -= 0xFFFF;
  }
  /*
   * If there's a single byte left over, checksum it, too.
   * Network byte order is big-endian, so the remaining byte is
   * the high byte.
   */
  if (i < len) {
	sum += addr[i] << 8;
	if (sum > 0xFFFF)
	  sum -= 0xFFFF;
  }
  return sum;
}

static inline uint16_t wrapsum(uint32_t sum)
{
  sum = ~sum & 0xFFFF;
  return (htons(sum));
}

#endif /* _PKTBUF_H_ */
