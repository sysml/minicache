/*
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
