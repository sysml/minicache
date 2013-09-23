#ifndef _DEBUG_H_
#define _DEBUG_H_

#define ENABLE_DEBUGGING /* uncomment this line to enable debug
                          * messages */

#define _NOOP for(;;){}

#ifdef ENABLE_DEBUGGING

#define dprintf(fmt, ...) do { printf("DEBUG: %s@%i: %s(): ", __FILE__, __LINE__, __FUNCTION__); printf((fmt), ##__VA_ARGS__); fflush(stdout); usleep(10000); } while(0)

#else

#define dprintf(fmt, ...) _NOOP

#endif
#endif /* _DEBUG_H_ */
