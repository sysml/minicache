#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <new>

#include <osv/device.h>
#include <osv/bio.h>
#include <sys/param.h>
#include <assert.h>
#include <sys/refcount.h>
#include <osv/mutex.h>
#include <osv/waitqueue.hh>

extern "C" {
int bio_isdone(struct bio *bio);
}

int
bio_isdone(struct bio *bio)
{
        int ret;

	WITH_LOCK(bio->bio_mutex) {
	  //SCOPE_LOCK(bio->bio_mutex);
	  ret = bio->bio_flags & BIO_DONE ? 1 : 0;
	}
	return ret;
}
