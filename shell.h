/*
 * MicroShell (µSh) for Mini-OS
 *
 * Copyright(C) 2013-2014 NEC Laboratories Europe. All rights reserved.
 *                        Simon Kuenzer <simon.kuenzer@neclab.eu>
 */
#ifndef _SHELL_H_
#define _SHELL_H_

#include <limits.h>
#include <stdio.h>

typedef int (*shfunc_ptr_t)(FILE *cio, int argc, char *argv[]);

#define SH_CLOSE INT_MAX

int init_shell(unsigned int en_lsess, unsigned int nb_rsess);
void exit_shell(void);

int shell_register_cmd(const char *cmd, shfunc_ptr_t func);
void shell_unregister_cmd(const char *cmd);

#endif /* _SHELL_H_ */
