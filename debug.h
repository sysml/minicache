#ifndef _DEBUG_H_
#define _DEBUG_H_

#include <mini-os/os.h>

extern uint64_t __dprintf_tsref;

#define init_debug() (__dprintf_tsref = NOW())


#ifdef ENABLE_DEBUG
/**
 * dprintf(): prints a debug message to stdout
 */
#define dprintf(fmt, ...)	\
	do { \
	    uint64_t mins = 0; \
	    uint64_t secs = 0; \
	    uint64_t usecs = 0; \
	     \
	    usecs = (NOW() - __dprintf_tsref) / 1000l; \
	    secs = usecs / 1000000l; \
	    usecs %= 1000000l; \
	    mins = secs / 60; \
	    secs %= 60; \
	     \
	    printf("[%lum%lu.%06lus] ", mins, secs, usecs); \
	    printf("%s:%4d: %s(): ",  __FILE__, __LINE__, __FUNCTION__); \
	    printf((fmt),               ##__VA_ARGS__); \
	} while(0)

/**
 * get_caller(): returns calling address for the current function
 *
 * Note: On non-x86 platforms, 0 is returned (32 and 64 bits)
 */
#ifdef __x86_64__
#define get_caller()	  \
	({ \
		unsigned long bp; \
		unsigned long *frame; \
		asm("movq %%rbp, %0":"=r"(bp)); \
		frame = (void*) bp; \
		frame[1]; \
	})
#elif defined __x86_32__
#define get_caller()	  \
	({ \
		unsigned long bp; \
		unsigned long *frame; \
		asm("movl %%ebp, %0":"=r"(bp)); \
		frame = (void*) bp; \
		frame[1]; \
	})
#else
#define get_caller() 0
#endif

#else /* ENABLE_DEBUG */

#define dprintf(fmt, ...) do {} while(0)
#define get_caller() 0

#endif /* ENABLE_DEBUG */
#endif /* _DEBUG_H_ */
