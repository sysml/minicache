/*
 * Simon's HashFS (SHFS) for Mini-OS
 *
 * Copyright(C) 2013-2014 NEC Laboratories Europe. All rights reserved.
 *                        Simon Kuenzer <simon.kuenzer@neclab.eu>
 */
#include <stdio.h>

#include "shell.h"

static int shcmd_lsdisk(FILE *cio, int argc, char *argv[])
{
	/* not ipmplemented yet */
	return 0;
}

int register_shfs_tools(void)
{
	int ret;
	ret = shell_register_cmd("lsdisk", shcmd_lsdisk);
	if (ret < 0)
		return ret;

	return 0;
}
