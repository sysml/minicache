/*
 * Simon's HashFS (SHFS) for Mini-OS
 *
 * Copyright(C) 2013-2014 NEC Laboratories Europe. All rights reserved.
 *                        Simon Kuenzer <simon.kuenzer@neclab.eu>
 */
#ifndef _SHFS_TOOLS_H_
#define _SHFS_TOOLS_H_

#include "shfs_defs.h"

/**
 * Registers shfs tools to micro shell
 */
int register_shfs_tools(void);

/**
 * Prints a uuid_t to a buffer (has to be at least 17 bytes long)
 */
void uuid_unparse(const uuid_t uu, char *out);

int uuid_compare(const uuid_t uu1, const uuid_t uu2);
int uuid_is_null(const uuid_t uu);
int uuid_is_zero(const uuid_t uu);
void uuid_copy(uuid_t dst, const uuid_t src);

static inline void hash_unparse(hash512_t h, uint8_t hlen, char *out)
{
	uint8_t i;

	for (i = 0; i < hlen; i++)
		snprintf(out + (2*i), 3, "%02x", h.u8[i]);
}

#endif /* _SHFS_TOOLS_H_ */
