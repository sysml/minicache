/*
 * Simon's HashFS (SHFS) for Mini-OS
 *
 * Copyright(C) 2013-2014 NEC Laboratories Europe. All rights reserved.
 *                        Simon Kuenzer <simon.kuenzer@neclab.eu>
 */
#include <stdio.h>
#include <hexdump.h>

#include "shfs.h"
#include "shfs_btable.h"
#include "shfs_tools.h"
#include "shfs_cache.h"
#include "shfs_fio.h"
#include "shell.h"
#include "ctldir.h"

static int shcmd_netcat(FILE *cio, int argc, char *argv[])
{
}

int register_testsuite(struct ctldir *cd)
{
	/* ctldir entries (ignore errors) */
	//if (cd) {}

	/* shell commands (ignore errors) */
	shell_register_cmd("netcat", shcmd_netcat);

	return 0;
}
