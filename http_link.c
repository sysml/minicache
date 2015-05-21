#include "http_link.h"

int httplink_init(struct http_srv *hs)
{
  hs->link_pool = alloc_simple_mempool(HTTP_MAXNB_LINKS, sizeof(struct http_req_link_origin));
  if (!hs->link_pool)
    return -ENOMEM;

  hs->nb_links = 0;
  hs->max_nb_links = HTTP_MAXNB_LINKS;
  dlist_init_head(hs->links);

  return 0;
}

void httplink_exit(struct http_srv *hs)
{
  BUG_ON(hs->nb_links != 0);

  free_mempool(hs->link_pool);
}

#if LWIP_DNS
void httpreq_link_dnscb(const char *name, ip_addr_t *ipaddr, void *argp)
{
  struct http_req *hreq = (struct http_req *) argp;
  struct http_req_link_origin *o = hreq->l.origin;

  if (!((ipaddr) && (ipaddr->addr))) {
    printd("Could not resolve '%s'\n", name);
    o->state = HRLO_ERROR;
  } else {
    printd("Name resolution for '%s' was successful\n", name);
    o->rip.addr = ipaddr->addr;
    o->state = HRLO_CONNECT;
  }

  httpsess_respond(hreq->hsess);
}
#endif

err_t httplink_connected(void *argp, struct tcp_pcb * tpcb, err_t err)
{
  struct http_req_link_origin *o = (struct http_req_link_origin *) argp;

  printd("Connection of origin %p extablished\n", o);
  return ERR_OK;
}

err_t httplink_sent(void *argp, struct tcp_pcb *tpcb, uint16_t len)
{
  struct http_req_link_origin *o = (struct http_req_link_origin *) argp;

  return ERR_OK;
}

err_t httplink_recv(void *argp, struct tcp_pcb *tpcb, struct pbuf *p, err_t err)
{
  struct http_req_link_origin *o = (struct http_req_link_origin *) argp;

  return ERR_OK;
}

void httplink_error(void *argp, err_t err)
{
  struct http_req_link_origin *o = (struct http_req_link_origin *) argp;

  printd("Killing origin connection %p due to error: %d\n", o, err);
  //httplink_close(hsess, HSC_KILL); /* drop connection */
}

err_t httplink_poll(void *argp, struct tcp_pcb *tpcb)
{
  struct http_req_link_origin *o = (struct http_req_link_origin *) argp;

  printd("Polling origin connection %p\n", o);
  if (o->state == HRLO_WAIT_CONNECT || o->state == HRLO_WAIT_REPLY) {
    --o->timeout;
    if (o->timeout == 0) {
      printd("Timeout expired\n", o);
      o->state = HRLO_ERROR;
      httplink_update_clients(o); /* notify clients */
    }
  }
  return ERR_OK;
}
