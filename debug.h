#ifndef _DEBUG_H_
#define _DEBUG_H_

#include <target/sys.h>
#include <sys/time.h>
#include <inttypes.h>

extern struct timeval __debug_tsref;

#define init_debug() (gettimeofday(&__debug_tsref, NULL))

#ifdef ENABLE_DEBUG
#ifdef __MINIOS__
#define __debug_printf(fmt, ...) printk((fmt), ##__VA_ARGS__)
#else
#define __debug_printf(fmt, ...) fprintf(stderr, (fmt), ##__VA_ARGS__)
#endif /* __MINIOS__ */

/**
 * printd(): prints a debug message to stdout
 */
#define printd(fmt, ...)						\
	do {								\
	    struct timeval now;					\
	    uint64_t mins, secs, usecs;				\
	    								\
	    gettimeofday(&now, NULL);					\
	    if (now.tv_usec < __debug_tsref.tv_usec) {			\
	        now.tv_usec += 1000000l;				\
	        now.tv_sec--;						\
	    }								\
	    usecs = (now.tv_usec - __debug_tsref.tv_usec);		\
	    								\
	    secs  = (now.tv_sec - __debug_tsref.tv_sec);		\
	    secs += usecs / 1000000l;					\
	    usecs %= 1000000l;						\
	    mins = secs / 60;						\
	    secs %= 60;						\
	    								\
	    __debug_printf("[%"PRIu64"m%02"PRIu64".%06"PRIu64"s] %s:%4d: %s(): " \
			   fmt, mins, secs, usecs,			\
			   __FILE__, __LINE__, __FUNCTION__,		\
			   ##__VA_ARGS__);				\
	} while(0)

/**
 * get_caller(): returns calling address for the current function
 *
 * Note: On non-x86 platforms, 0xBADC0DED is returned
 */
#if defined __MINIOS__ && defined __x86_64__
#define get_caller()	  \
	({ \
		unsigned long bp; \
		unsigned long *frame; \
		asm("movq %%rbp, %0":"=r"(bp)); \
		frame = (void*) bp; \
		frame[1]; \
	})
#elif defined __MINIOS__ && defined __x86_32__
#define get_caller()	  \
	({ \
		unsigned long bp; \
		unsigned long *frame; \
		asm("movl %%ebp, %0":"=r"(bp)); \
		frame = (void*) bp; \
		frame[1]; \
	})
#else
#define get_caller() 0xBADC0DED
#endif

#else /* ENABLE_DEBUG */

#define printd(fmt, ...) do {} while(0)
#define get_caller() 0xDEADC0DE

#endif /* ENABLE_DEBUG */
#endif /* _DEBUG_H_ */
