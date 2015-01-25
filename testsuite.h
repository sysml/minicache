#ifndef _TESTSUITE_H_
#define _TESTSUITE_H_

#include "shfs_defs.h"
#ifdef HAVE_CTLDIR
#include <target/ctldir.h>
#endif

/**
 * Registers testsuite to micro shell + ctldir (if *cd is not NULL)
 */
#ifdef HAVE_CTLDIR
int register_testsuite(struct ctldir *cd);
#else
int register_testsuite(void);
#endif

#endif /* _TESTSUITE_H_ */
