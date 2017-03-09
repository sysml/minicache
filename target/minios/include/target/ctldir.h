/*
 * Control Trigger Interface module for XenStore
 *
 * Authors: Simon Kuenzer <simon.kuenzer@neclab.eu>
 *
 *
 * Copyright (c) 2013-2017, NEC Europe Ltd., NEC Corporation All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * THIS HEADER MAY NOT BE EXTRACTED OR MODIFIED IN ANY WAY.
 */
#ifndef _CTLDIR_H_
#define _CTLDIR_H_

#include <mini-os/kernel.h>
#include <mini-os/errno.h>
#include <mini-os/sched.h>
#include <stdio.h>
#include <limits.h>
#include "shell.h"

#define CTLDIR_MAX_TRIGGERS 16
#define CTLDIR_MAX_NAMELEN 32

//typedef int (*shfunc_ptr_t)(FILE *cio, int argc, char *argv[]);

typedef char *(*ctldfunc_ptr_t)(void *cookie, char *arg);

struct ctldir {
	char basename[CTLDIR_MAX_NAMELEN];
	char threadname[CTLDIR_MAX_NAMELEN + 9];
	struct thread *watcher;
	xenbus_event_queue xseq;

	const char *lock_name;

	uint32_t nb_trigger;
	char *trigger_name[CTLDIR_MAX_TRIGGERS];
	char *trigger_ipath[CTLDIR_MAX_TRIGGERS];
	char *trigger_opath[CTLDIR_MAX_TRIGGERS];
	ctldfunc_ptr_t trigger_func[CTLDIR_MAX_TRIGGERS];
	void *trigger_cookie[CTLDIR_MAX_TRIGGERS];
	unsigned int trigger_ignore[CTLDIR_MAX_TRIGGERS];
};

struct ctldir *create_ctldir(const char *name);

int ctldir_register_trigger(struct ctldir *ctld, const char *name, ctldfunc_ptr_t func, void *cookie);
int ctldir_register_shcmd(struct ctldir *ctld, const char *name, shfunc_ptr_t func);

int ctldir_start_watcher(struct ctldir *ctld);

#endif /* _CTLDIR_H_ */
