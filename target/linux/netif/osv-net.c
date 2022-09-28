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

#include <netif/osv-net.h>

#include "likely.h"
#include "lwip/def.h"
#include "lwip/mem.h"
#include "lwip/pbuf.h"
#include <lwip/stats.h>
#include <lwip/snmp.h>

#include <hexdump.h>

#define OSVNETIF_NPREFIX 'o'
#define OSVNETIF_SPEED 0ul     /* 0 for unknown */
#define OSVNETIF_MTU 1400

/**
 * Helper macro
 */
#ifndef min
#define min(a, b)						\
    ({ __typeof__ (a) __a = (a);				\
       __typeof__ (b) __b = (b);				\
       __a < __b ? __a : __b; })
#endif

/**
 * This function does the actual transmission of a packet. The packet is
 * contained in the pbuf that is passed to the function. This pbuf
 * can be chained.
 *
 * @param netif
 *  the lwip network interface structure for this osvnetif
 * @param p
 *  the packet to send (e.g. IP packet including MAC addresses and type)
 * @return
 *  ERR_OK when the packet could be sent; an err_t value otherwise
 */
static err_t osvnetif_output(struct netif *netif, struct pbuf *p,
			     const ip_addr_t *ipaddr)
{
    struct osvnetif *nfi = netif->state;
    struct pbuf *q;
    unsigned char *cur;

    LWIP_DEBUGF(NETIF_DEBUG, ("osvnetif_transmit: %c%c: "
			      "Transmitting %u bytes\n",
			      netif->name[0], netif->name[1],
			      p->tot_len));
    if (!p->next) {
        /* fast case: no further buffer allocation needed */
        onio_transmit(nfi->dev, (unsigned char *) p->payload, p->len);
    } else {
        unsigned char data[p->tot_len];

        for(q = p, cur = data; q != NULL; cur += q->len, q = q->next)
            MEMCPY(cur, q->payload, q->len);

        onio_transmit(nfi->dev, data, p->tot_len);
    }
    LINK_STATS_INC(link.xmit);
    return ERR_OK;
}

/**
 * Allocates a pbuf and copies data into it
 *
 * @param data
 *  the pointer to packet data to be copied into the pbuf
 * @param len
 *  the length of data in bytes
 * @return
 *  NULL when a pbuf could not be allocated; the pbuf otherwise
 */
static struct pbuf *osvnetif_mkpbuf(const unsigned char *data, int len)
{
    struct pbuf *p, *q;
    const unsigned char *cur;

    p = pbuf_alloc(PBUF_RAW, len, PBUF_POOL);
    if (unlikely(!p))
        return NULL;

    if (likely(!p->next)) {
        /* fast path */
        MEMCPY(p->payload, data, len);
    } else {
        /* pbuf chain */
        for(q = p, cur = data; q != NULL; cur += q->len, q = q->next)
            MEMCPY(q->payload, cur, q->len);
    }

    return p;
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
 *  the lwip network interface structure for this osvnetif
 */
static inline void osvnetif_input(struct pbuf *p, struct netif *netif)
{
    err_t err;

    LWIP_DEBUGF(NETIF_DEBUG, ("osvnetif_input: %c%c: "
			      "Received %u bytes\n",
			      netif->name[0], netif->name[1],
			      p->tot_len));

    /* packet will be sent to lwIP stack for processing */
    /* Note: On threaded configuration packet buffer will be enqueued on
     *  a mailbox. The lwIP thread will do the packet processing when it gets
     *  scheduled. */
    err = netif->input(p, netif);
    if (unlikely(err != ERR_OK)) {
#ifndef CONFIG_LWIP_NOTHREADS
      if (err == ERR_MEM)
	LWIP_DEBUGF(NETIF_DEBUG, ("osvnetif_input: %c%c: ERROR %d: "
				  "Could not post packet to lwIP thread. Packet dropped\n",
				  netif->name[0], netif->name[1], err));
      else
#endif /* CONFIG_LWIP_NOTHREADS */
	LWIP_DEBUGF(NETIF_DEBUG, ("osvnetif_input: %c%c: ERROR %d: "
				  "Packet dropped\n",
				  netif->name[0], netif->name[1], err));
      pbuf_free(p);
    }
}

/**
 * Callback to netfront that pushed a received packet to lwIP.
 * Is is called by osvnetif_poll() for each received packet.
 *
 * @param data
 *  the pointer to received packet data
 * @param len
 *  the length of data in bytes
 * @param argp
 *  pointer to netif
 */
static void osvnetif_rx_handler(struct pbuf *p, void *argp)
{
    struct netif *netif = argp;
    LINK_STATS_INC(link.recv);
    osvnetif_input(p, netif);
}

#ifndef CONFIG_LWIP_NOTHREADS
/**
 * Network polling thread function
 *
 * @param argp
 *  pointer to netif
 */
/* TODO: Use mini-os's blocking poll */
static void osvnetif_thread(void *argp)
{
    struct netif *netif = argp;
    struct osvnetif *nfi = netif->state;
    onio *dev = nfi->dev;

    while (likely(!nfi->_thread_exit)) {
        onio_poll(dev);
        schedule();
    }

    nfi->_thread_exit = 0;
}
#endif /* CONFIG_LWIP_NOTHREADS */

#if LWIP_NETIF_REMOVE_CALLBACK
/**
 * Closes a network interface.
 * This function is called by lwIP on netif_remove().
 *
 * @param netif
 *  the lwip network interface structure for this osvnetif
 */
static void osvnetif_exit(struct netif *netif)
{
    struct osvnetif *nfi = netif->state;

    close_onio(nfi->dev);

#ifndef CONFIG_LWIP_NOTHREADS
    LWIP_DEBUGF(NETIF_DEBUG, ("osvnetif_exit: wait for thread shutdown\n"));
    nfi->_thread_exit = 1; /* request exit */
    while (nfi->_thread_exit)
        schedule();
    LWIP_DEBUGF(NETIF_DEBUG, ("osvnetif_exit: thread was shutdown\n"));
#endif /* CONFIG_LWIP_NOTHREADS */

    if (nfi->_state_is_private) {
	mem_free(nfi);
	netif->state = NULL;
    }
}
#endif /* LWIP_NETIF_REMOVE_CALLBACK */

/**
 * Initializes and sets up a netfront interface for lwIP.
 * This function should be passed as a parameter to osvnetif_add().
 *
 * @param netif
 *  the lwip network interface structure for this osvnetif
 * @return
 *  ERR_OK if the interface was successfully initialized;
 *  An err_t value otherwise
 */
err_t osvnetif_init(struct netif *netif)
{
    struct osvnetif *nfi;
    static uint8_t osvnetif_id = 0;

    LWIP_ASSERT("netif != NULL", (netif != NULL));

    if (!(netif->state)) {
	nfi = mem_calloc(1, sizeof(*nfi));
	if (!nfi) {
	    LWIP_DEBUGF(NETIF_DEBUG, ("osvnetif_init: "
				      "Could not allocate \n"));
	    goto err_out;
	}
	netif->state = nfi;
	nfi->_state_is_private = 1;
	nfi->_dev_is_private = 1;
	nfi->_hwaddr_is_private = 1;
    } else {
	nfi = netif->state;
	nfi->_state_is_private = 0;
	nfi->_dev_is_private = !(nfi->dev);
	nfi->_hwaddr_is_private = eth_addr_cmp(&nfi->hwaddr, &ethzero);
    }

    /* Netfront */
    if (nfi->_dev_is_private) {
	/* user did not provide an opened netfront, we need to do it here */
	if (!nfi->_state_is_private) {
	  /* use vif_id to open an specific NIC interface */
	  char ifname[16];
	  snprintf(ifname, sizeof(ifname), "eth%u", nfi->vif_id);
	  nfi->dev = open_onio(ifname,
			       osvnetif_mkpbuf,
			       osvnetif_rx_handler, netif);
	} else {
	    /* open eth0 interface */
	  nfi->dev = open_onio(NULL,
			       osvnetif_mkpbuf,
			       osvnetif_rx_handler, netif);
	}
	if (!nfi->dev) {
	    LWIP_DEBUGF(NETIF_DEBUG, ("osvnetif_init: "
				      "Could not init onio\n"));
	    goto err_free_nfi;
	}
    }

    /* Interface identifier */
    netif->name[0] = OSVNETIF_NPREFIX;
    netif->name[1] = '0' + osvnetif_id;
    osvnetif_id++;

    /* We send IP packets directly (ARP is done by OSv) */
    netif->output =  osvnetif_output;
    netif->linkoutput = NULL;
#if LWIP_NETIF_REMOVE_CALLBACK
    netif->remove_callback = osvnetif_exit;
#endif /* CONFIG_NETIF_REMOVE_CALLBACK */

    /* No hardware address support */
    netif->hwaddr_len = 0;

    /* Initialize the snmp variables and counters inside the struct netif.
     * The last argument is the link speed, in units of bits per second. */
    NETIF_INIT_SNMP(netif, snmp_ifType_ppp, OSVNETIF_SPEED);
    LWIP_DEBUGF(NETIF_DEBUG, ("osvnetif_init: %c%c: Link speed: %llu bps\n",
			      netif->name[0], netif->name[1], OSVNETIF_SPEED));

    /* Device capabilities */
    netif->flags = NETIF_FLAG_LINK_UP;

    /* Maximum transfer unit */
    netif->mtu = OSVNETIF_MTU;
    LWIP_DEBUGF(NETIF_DEBUG, ("osvnetif_init: %c%c: MTU: %u\n",
			      netif->name[0], netif->name[1], netif->mtu));

#if LWIP_NETIF_HOSTNAME
    /* Initialize interface hostname */
    if (!netif->hostname)
	netif->hostname = NULL;
#endif /* LWIP_NETIF_HOSTNAME */

#ifndef CONFIG_LWIP_NOTHREADS
  nfi->_thread_exit = 0;
  nfi->_thread_name[0] = netif->name[0];
  nfi->_thread_name[1] = netif->name[1];
  nfi->_thread_name[2] = '-';
  nfi->_thread_name[3] = 'r';
  nfi->_thread_name[4] = 'x';
  nfi->_thread_name[5] = '\0';
  create_thread(nfi->_thread_name, osvnetif_thread, netif);
#endif /* CONFIG_LWIP_NOTHREADS */

    return ERR_OK;

err_close_onio:
    close_onio(nfi->dev);
err_free_nfi:
    if (nfi->_state_is_private) {
	mem_free(nfi);
	netif->state = NULL;
    }
err_out:
    return ERR_IF;
}
