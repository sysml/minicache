#ifndef _TESTSUITE_H_
#define _TESTSUITE_H_

#include "shfs_defs.h"
#include "ctldir.h"

/**
 * Registers testsuite to micro shell + ctldir (if *cd is not NULL)
 */
int register_testsuite(struct ctldir *cd);

#endif /* _TESTSUITE_H_ */
