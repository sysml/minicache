/*
 * Simon's HashFS (SHFS) for Mini-OS
 *
 * Copyright(C) 2013-2014 NEC Laboratories Europe. All rights reserved.
 *                        Simon Kuenzer <simon.kuenzer@neclab.eu>
 */
#ifndef _SHFS_TOOLS_H_
#define _SHFS_TOOLS_H_

#include "shfs_defs.h"
#ifdef HAVE_CTLDIR
#include <target/ctldir.h>
#endif

/**
 * Registers shfs tools to micro shell + ctldir (if *cd is not NULL)
 */
#ifdef HAVE_CTLDIR
int register_shfs_tools(struct ctldir *cd);
#else
int register_shfs_tools(void);
#endif

/**
 * Prints an uuid/hash number to a buffer
 * Note: The target buffer for the UUID has to be at least 37 bytes long
 * Note: The target buffer for the hash has to be at least ((2 * hlen) + 1) bytes long
 */
#ifdef __MINIOS__
void uuid_unparse(const uuid_t uu, char *out);
#endif
void hash_unparse(const hash512_t h, uint8_t hlen, char *out);

size_t strftimestamp_s(char *s, size_t slen, const char *fmt, uint64_t ts_sec);

#endif /* _SHFS_TOOLS_H_ */
