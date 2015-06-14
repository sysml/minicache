/*
 * MicroShell (µSh) for Mini-OS
 *
 * Copyright(C) 2013-2015 NEC Laboratories Europe. All rights reserved.
 *                        Simon Kuenzer <simon.kuenzer@neclab.eu>
 */
#ifndef _SHELL_EXTRAS_H_
#define _SHELL_EXTRAS_H_

#ifdef HAVE_CTLDIR
#include <target/ctldir.h>
#endif

/**
 * Registers shfs tools to micro shell + ctldir (if *cd is not NULL)
 */
#ifdef HAVE_CTLDIR
int register_shell_extras(struct ctldir *cd);
#else
int register_shell_extras(void);
#endif

#endif /* _SHELL_EXTRAS_H_ */
