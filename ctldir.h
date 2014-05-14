#ifndef _CTLDIR_H_
#define _CTLDIR_H_

#include <mini-os/kernel.h>
#include <mini-os/errno.h>
#include <mini-os/sched.h>

#define CTLDIR_MAX_TRIGGERS 16
#define CTLDIR_MAX_NAMELEN 32

typedef char *(*cdfunc_ptr_t)(void *cookie, char *arg);

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
	cdfunc_ptr_t trigger_func[CTLDIR_MAX_TRIGGERS];
	void *trigger_cookie[CTLDIR_MAX_TRIGGERS];
	unsigned int trigger_ignore[CTLDIR_MAX_TRIGGERS];
};

struct ctldir *create_ctldir(const char *name);
int ctldir_register_trigger(struct ctldir *cd, const char *name, cdfunc_ptr_t func, void *cookie);
int ctldir_start_watcher(struct ctldir *cd);

#endif /* _CTLDIR_H_ */
