#include "http_link.h"

int http_link_init(struct http_srv *hs)
{
  hs->link_pool = alloc_simple_mempool(HTTP_MAXNB_LINKS, sizeof(struct http_req_link_origin));
  if (!hs->link_pool)
    return -ENOMEM;

  hs->nb_links = 0;
  hs->max_nb_links = HTTP_MAXNB_LINKS;
  dlist_init_head(hs->links);

  return 0;
}

void http_link_exit(struct http_srv *hs)
{
  BUG_ON(hs->nb_links != 0);

  free_mempool(hs->link_pool);
}
