/*
 * Control Trigger Interface client for XenStore
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
 */
#ifndef _CTLTRIGGER_H_
#define _CTLTRIGGER_H_

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#define STR_VERSION "XenStore Control Action Trigger v0.01"

struct args {
	unsigned int domid;
	char *scope;
	char *trigger;
	char *args; /* malloc'd */
	int nowait;
};

/*
 * Print helpers
 */
extern unsigned int verbosity;
extern int force;

#define eprintf(...)		fprintf(stderr, __VA_ARGS__)
#define fatal()			eprintf("%s\n", strerror(errno))
#define dief(...)		do { eprintf(__VA_ARGS__); exit(EXIT_FAILURE); } while(0)
#define die()			do { fatal(); exit(EXIT_FAILURE); } while(0)
#define dprintf(LEVEL, ...)	do { if (verbosity >= (LEVEL)) fprintf(stderr, __VA_ARGS__); } while(0)
#define printvar(VAR, FMT)	do { if (verbosity >= (D_MAX)) fprintf(stderr, #VAR ": "#FMT"\n", (VAR)); } while(0)

#define D_L0		1
#define D_L1		2
#define D_MAX		D_L1

/*
 * Argument parsing helper
 */
static inline int parse_args_setval_str(char** out, const char* buf)
{
	if (*out)
		free(*out);
	*out = strdup(buf);
	if (!*out) {
		*out = NULL;
		return -ENOMEM;
	}

	return 0;
}

static inline int parse_args_setval_int(int* out, const char* buf)
{
	if (sscanf(optarg, "%d", out) != 1)
		return -EINVAL;
	return 0;
}

#endif /* _CTLTRIGGER_H_ */
