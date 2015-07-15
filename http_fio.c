#include "http_fio.h"

void httpreq_fio_aiocb(SHFS_AIO_TOKEN *t, void *cookie, void *argp)
{
	struct http_req *hreq = (struct http_req *) cookie;

	printd("Chunk %"PRIchk" loaded (cce: %p, t: %p/%p)\n", hreq->f.cce[hreq->f.cce_idx]->addr, hreq->f.cce[hreq->f.cce_idx], hreq->f.cce_t, t);

	BUG_ON(t != hreq->f.cce_t);
	BUG_ON(hreq->state != HRS_RESPONDING_MSG);

	shfs_aio_finalize(t);
	hreq->f.cce_t = NULL;

	/* continue sending */
	printd("** [cce] request done, calling httpsess_respond()\n");
	httpsess_respond(hreq->hsess);
}
