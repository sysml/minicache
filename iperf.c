#include <mini-os/os.h>
#include <mini-os/types.h>
#include <mini-os/xmalloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <kernel.h>
#include <sched.h>
#include <mempool.h>

#include <lwip/tcp.h>

#include "iperf.h"

#define SESSMP_NBOBJ 128
#define IPERF_PORT 5001

struct iperfsrv {
    struct tcp_pcb *tpcb;
    struct mempool *sessmp;

    uint32_t refcount;
};

enum iperfsrv_state
{
  ES_NONE = 0,
  ES_ACCEPTED,
  ES_RECEIVED,
  ES_CLOSING
};

struct iperfsrv_sess {
    struct mempool_obj *obj; /* reference to mempool object where
                              * this struct is embedded in */
    struct iperfsrv *server;
    struct tcp_pcb *tpcb;
    enum iperfsrv_state state;
    uint8_t retries;
    /* pbuf (chain) to recycle */
    struct pbuf *p;
};

static void iperfsrv_sessmp_objinit(struct mempool_obj *obj, void *unused)
{
    struct iperfsrv_sess *sess = obj->data;
    LWIP_UNUSED_ARG(unused);

    sess->obj = obj;
}

static err_t iperfsrv_accept(void *argp, struct tcp_pcb *new_tpcb, err_t err);
static void iperfsrv_close(struct iperfsrv_sess *sess);
static err_t iperfsrv_recv(void *argp, struct tcp_pcb *tpcb, struct pbuf *p, err_t err);
static err_t iperfsrv_sent(void *argp, struct tcp_pcb *tpcb, u16_t len);
static void iperfsrv_error(void *argp, err_t err);
static void iperfsrv_send(struct iperfsrv_sess *sess);

static struct iperfsrv *server = NULL; /* server instance */

int register_iperfsrv(void)
{
    err_t err;
    int ret = 0;

    ASSERT(server == NULL);

    server = _xmalloc(sizeof(struct iperfsrv), 64);
    if (!server) {
        ret = -ENOMEM;
        goto out;
    }

    server->sessmp = alloc_mempool(SESSMP_NBOBJ, sizeof(struct iperfsrv_sess), \
                                   64, 0, 0, iperfsrv_sessmp_objinit, NULL, 0);
    if (!server->sessmp) {
        ret = -ENOMEM;
        goto out_free_server;
    }
    server->refcount = 0;

    server->tpcb = tcp_new();
    if (!server->tpcb) {
        ret = -ENOMEM;
        goto out_free_mp;
    }

    err = tcp_bind(server->tpcb, IP_ADDR_ANY, IPERF_PORT);
    if (err != ERR_OK) {
        ret = -ENOMEM;
        goto out_close_server;
    }

    server->tpcb = tcp_listen(server->tpcb); /* transform it to a listener */
    tcp_arg(server->tpcb, server); /* set callback argp */
    tcp_accept(server->tpcb, iperfsrv_accept); /* set accept callback */

    printf("IPerf server started\n");
    return 0;

out_close_server:
    tcp_close(server->tpcb);
out_free_mp:
    free_mempool(server->sessmp);
out_free_server:
    xfree(server);
out:
    return ret;
}

void unregister_iperfsrv(void)
{
    ASSERT(server != NULL);
    ASSERT(server->refcount == 0);

    tcp_close(server->tpcb);
    free_mempool(server->sessmp);
    xfree(server);
    server = NULL;
}

static err_t iperfsrv_accept(void *argp, struct tcp_pcb *new_tpcb, err_t err)
{
    struct iperfsrv *server = argp;
    struct mempool_obj *obj;
    struct iperfsrv_sess *sess;

    LWIP_UNUSED_ARG(err);

    obj = mempool_pick(server->sessmp);
    if (!obj)
        return ERR_MEM;

    sess = obj->data;
    sess->retries = 0;
    sess->server = server;
    sess->state = ES_ACCEPTED;
    sess->tpcb = new_tpcb;

    /* register callbacks for this connection */
    tcp_arg(new_tpcb, sess);
    tcp_recv(new_tpcb, iperfsrv_recv);
    tcp_err(new_tpcb, iperfsrv_error);
    tcp_sent(new_tpcb, NULL);
    tcp_poll(new_tpcb, NULL, 0);
    tcp_setprio(new_tpcb, TCP_PRIO_MAX);

    server->refcount++;
    return ERR_OK;
}

static void iperfsrv_close(struct iperfsrv_sess *sess)
{
    /* unregister session */
    sess->server->refcount--;

    /* disable tcp connection */
    tcp_arg(sess->tpcb, NULL);
    tcp_sent(sess->tpcb, NULL);
    tcp_recv(sess->tpcb, NULL);
    tcp_sent(sess->tpcb, NULL);
    tcp_err(sess->tpcb, NULL);
    tcp_poll(sess->tpcb, NULL, 0);

    /* release memory */
    tcp_close(sess->tpcb);
    mempool_put(sess->obj);
}

/*----------------------------------------------------------------------------
 * The following code is ported from:
 *  http://docs.lpcware.com/lpcopen/v1.03/lpc17xx__40xx_2examples_2misc_2iperf__server_2iperf__server_8c_source.html
 *----------------------------------------------------------------------------*/

static err_t iperfsrv_recv(void *argp, struct tcp_pcb *tpcb, struct pbuf *p, err_t err)
{
    struct iperfsrv_sess *sess = argp;
    err_t ret_err;
    u16_t plen;

    if (!p) {
        /* remote host closed connection */
        sess->state = ES_CLOSING;
        iperfsrv_close(sess);
        return ERR_OK;
    } else if (err != ERR_OK) {
        /* cleanup, for unkown reason */
        if (p) {
            sess->p = NULL;
            pbuf_free(p);
        }
        return err;
    }

    switch (sess->state) {
    case ES_ACCEPTED:
        /* receive the package and discard it silently for testing
           reception bandwidth */
        sess->p = p;
        plen = p->len;
        pbuf_free(p);
        tcp_recved(tpcb, p->tot_len);
        ret_err = ERR_OK;
        break;
    case ES_CLOSING:
        /* odd case, remote side closing twice, trash data */
        tcp_recved(tpcb, p->tot_len);
        sess->p = NULL;
        pbuf_free(p);
        ret_err = ERR_OK;
        break;
    default:
        /* unkown es->state, trash data  */
        tcp_recved(tpcb, p->tot_len);
        sess->p = NULL;
        pbuf_free(p);
        ret_err = ERR_OK;
        break;
    }

    return ret_err;
}

static void iperfsrv_error(void *argp, err_t err)
{
    struct iperfsrv_sess *sess = argp;
    LWIP_UNUSED_ARG(err);

    if (sess)
        iperfsrv_close(sess);
}

static err_t iperfsrv_sent(void *argp, struct tcp_pcb *tpcb, u16_t len)
{
    struct iperfsrv_sess *sess = argp;
    LWIP_UNUSED_ARG(len);

    sess->retries = 0;
    if(sess->p) {
        /* still got pbufs to send */
        tcp_sent(tpcb, iperfsrv_sent);
        iperfsrv_send(sess);
    } else {
        /* no more pbufs to send */
        if(sess->state == ES_CLOSING) {
            iperfsrv_close(sess);
        }
    }
    return ERR_OK;
}

static void iperfsrv_send(struct iperfsrv_sess *sess)
{
    struct tcp_pcb *tpcb = sess->tpcb;
    struct pbuf *p;
    err_t wr_err;
    u16_t plen;
    u8_t freed;

    while ((sess->p) &&
           (sess->p->len <= tcp_sndbuf(tpcb)))
    {
        p = sess->p;

        /* enqueue data for transmission */
        wr_err = tcp_write(tpcb, p->payload, p->len, TCP_WRITE_FLAG_COPY);
        if (wr_err != ERR_OK) {
            switch (wr_err) {
            case ERR_MEM:
                /* we are low on memory, try later / harder, defer to poll */
                sess->p = p;
                break;
            default:
                /* other problem ?? */
                break;
            }
            return;
        }
        plen = p->len;

        /* continue with next pbuf in chain (if any) */
        sess->p = p->next;
        if(sess->p) {
            /* new reference! */
            pbuf_ref(sess->p);
        }

        /* chop first pbuf from chain */
        do {
            /* try hard to free pbuf */
            freed = pbuf_free(p);
        } while (freed == 0);

        /* we can read more data now */
        tcp_recved(tpcb, plen);
    }
}
