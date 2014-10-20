#include <mini-os/os.h>
#include <mini-os/xenbus.h>
#include <mini-os/xmalloc.h>
#include <mini-os/wait.h>
#include <mini-os/sched.h>
#include <mini-os/lib.h>
#include <fcntl.h>
#include <unistd.h>
#include "ctldir.h"

#define SHWRAPPER_MAX_NB_ARGS 96
#define DOM0 ((domid_t) 0)

#define _xb_write(xbt, path, value) ({ \
	char *__xb_errmsg; \
	__xb_errmsg = xenbus_write((xbt), (path), (value)); \
	if (__xb_errmsg) { \
		printk("%s:%u: xenbus_write(%s) failed: %s\n", \
		       __FILE__, __LINE__, (path), __xb_errmsg); \
		free(__xb_errmsg); \
	} \
	__xb_errmsg ? -1: 0; })
#define _xb_read(xbt, path, value_ptr) ({ \
	char *__xb_errmsg; \
	__xb_errmsg = xenbus_read((xbt), (path), (value_ptr)); \
	if (__xb_errmsg) { \
		printk("%s:%u: xenbus_read(%s) failed: %s\n", \
		       __FILE__, __LINE__, (path), __xb_errmsg); \
		free(__xb_errmsg); \
	} \
	__xb_errmsg ? -1: 0; })
#ifndef CTLDIR_NOCHMOD
#define _xb_chmod(path, domid, domperm) ({ \
	char *__xb_errmsg; \
	__xb_errmsg = xenbus_set_perms(XBT_NIL, (path), (domid), (domperm)); \
	if (__xb_errmsg) { \
		printk("%s:%u: xenbus_set_perms(%s) failed: %s\n",  \
		       __FILE__, __LINE__, (path), __xb_errmsg); \
		free(__xb_errmsg); \
	} \
	__xb_errmsg ? -1: 0; })
#endif /* CTLDIR_NOCHMOD */
#define _xb_rm(path) ({ \
	char *__xb_errmsg; \
	__xb_errmsg = xenbus_rm(XBT_NIL, (path)); \
	if (__xb_errmsg) { \
		printk("%s:%u: xenbus_set_perms(%s) failed: %s\n", \
		       __FILE__, __LINE__, (path), __xb_errmsg); \
		free(__xb_errmsg); \
	} \
	__xb_errmsg ? -1: 0; })
#define _xb_begin_transaction(xbt_ptr) ({ \
	char *__xb_errmsg; \
	__xb_errmsg = xenbus_transaction_start((xbt_ptr)); \
	if (__xb_errmsg) { \
		printk("%s:%u: xenbus_transaction_start(%p) failed: %s\n", \
		       __FILE__, __LINE__, (xbt_ptr), __xb_errmsg); \
		free(__xb_errmsg); \
	} \
	__xb_errmsg ? -1: 0; })
#define _xb_submit_transaction(xbt) ({ \
	char *__xb_errmsg; \
	int __xb_retry; \
	__xb_errmsg = xenbus_transaction_end((xbt), 0, &__xb_retry); \
	if (__xb_errmsg) { \
		printk("%s:%u: xenbus_transaction_end(%p) failed: %s\n", \
		       __FILE__, __LINE__, &(xbt), __xb_errmsg); \
		free(__xb_errmsg); \
	} \
	__xb_errmsg ? -1: ( __xb_retry ? -EINTR : 0); })
#define _xb_abort_transaction(xbt) ({ \
	char *__xb_errmsg; \
	int __xb_retry; \
	__xb_errmsg = xenbus_transaction_end((xbt), 1, &__xb_retry); \
	if (__xb_errmsg) { \
		printk("%s:%u: xenbus_transaction_end(%p) failed: %s\n", \
		       __FILE__, __LINE__, &(xbt), __xb_errmsg); \
		free(__xb_errmsg); \
	} \
	__xb_errmsg ? -1: 0; })
#define _xb_watch_token(path, token, xseq) ({ \
	char *__xb_errmsg; \
	__xb_errmsg = xenbus_watch_path_token(XBT_NIL, (path), (token), (xseq)); \
	if (__xb_errmsg) { \
		printk("%s:%u: xenbus_watch_path_token(%s:%s) failed: %s\n", \
		       __FILE__, __LINE__, (path), (token), __xb_errmsg); \
		free(__xb_errmsg); \
	} \
	__xb_errmsg ? -1: 0; })

#define _xb_unwatch_token(path, token) ({ \
	char *__xb_errmsg; \
	__xb_errmsg = xenbus_unwatch_path_token(XBT_NIL, (path), (token)); \
	if (__xb_errmsg) { \
		printk("%s:%u: xenbus_watch_unpath_token(%s:%s) failed: %s\n", \
		       __FILE__, __LINE__, (path), (token), __xb_errmsg); \
		free(__xb_errmsg); \
	} \
	__xb_errmsg ? -1: 0; })

/* -------------------------------------------------------------------------
 * Dirty, ugly, and hacky addition to xenbus.h API
 *  This extends xenbus.h with a waiter function that returns the event
 *  so that its token can be accessed/evaluated
 *  --> should be moved to xenbus.h
 */
extern struct wait_queue_head xenbus_watch_queue;
extern xenbus_event_queue xenbus_events;

static struct xenbus_event *xenbus_wait_for_watch_return_event(xenbus_event_queue *queue)
{
    struct xenbus_event *event;
    DEFINE_WAIT(w);
    if (!queue)
        queue = &xenbus_events;
    while (!(event = *queue)) {
        add_waiter(w, xenbus_watch_queue);
        schedule();
    }
    remove_waiter(w, xenbus_watch_queue);
    *queue = event->next;
    return event;
}
/* ------------------------------------------------------------------------- */


static void ctldir_watcherthread(void *argp);

struct ctldir *create_ctldir(const char *name) {
	struct ctldir *cd;
	int ret;

	cd = _xmalloc(sizeof(*cd), 0);
	if (!cd) {
		errno = ENOMEM;
		goto err_out;
	}

	strncpy(cd->basename, name, sizeof(cd->basename) - 1);
	cd->basename[sizeof(cd->basename) - 1] = '\0';
	snprintf(cd->threadname, sizeof(cd->threadname), "ctlwatch-%s", cd->basename);
	cd->watcher = NULL;
	cd->lock_name = "lock";
	cd->nb_trigger = 0;
	cd->xseq = NULL;

	/* create base dir or check if it is writable */
	ret = _xb_write(XBT_NIL, cd->basename, "");
	if (ret < 0) {
		errno = EACCES;
		goto err_free_cd;
	}

	return cd;

 err_free_cd:
	free(cd);
 err_out:
	return NULL;
}

int ctldir_register_trigger(struct ctldir *cd, const char *name, cdfunc_ptr_t func, void *cookie)
{
	register uint32_t i = cd->nb_trigger;
	size_t len;

	BUG_ON(cd->watcher != NULL);

	if (i >= CTLDIR_MAX_TRIGGERS)
		return -ENOSPC;

	cd->trigger_name[i] = strndup(name, CTLDIR_MAX_NAMELEN);
	if (!cd->trigger_name[i])
		goto err_out;

	len = strlen(name) + strlen(cd->basename) + 2 + 3;
	cd->trigger_ipath[i] = malloc(len);
	if (!cd->trigger_ipath[i])
		goto err_free_name;
	snprintf(cd->trigger_ipath[i], len,
	         "%s/%s-in", cd->basename, cd->trigger_name[i]);

	len = strlen(name) + strlen(cd->basename) + 2 + 4;
	cd->trigger_opath[i] = malloc(len);
	if (!cd->trigger_opath[i])
		goto err_free_ipath;
	snprintf(cd->trigger_opath[i], len,
	         "%s/%s-out", cd->basename, cd->trigger_name[i]);

	cd->trigger_func[i] = func;
	cd->trigger_cookie[i] = cookie;
	++cd->nb_trigger;

	return 0;

 err_free_ipath:
	free(cd->trigger_ipath[i]);
 err_free_name:
	free(cd->trigger_name[i]);
 err_out:
	return -ENOMEM;
}

static char *_shcmd_wrapper(void *cookie, char *argb)
{
	shfunc_ptr_t shcmd = (shfunc_ptr_t) cookie;
	char *argv[SHWRAPPER_MAX_NB_ARGS];
	int argc;
	int ret;
	char *reply;
	int cfd;
	FILE *cio;
	int prev_was_whitespace;
	size_t i;

	/* open a console I/O for the command (here: standard console) */
	cfd = open("/var/log/", O_RDWR); /* workaround to access stdin/stdout */
	if (cfd < 0)
		goto err_out; /* ignore call: couldn't open console device */
	cio = fdopen(cfd, "r+");

	/* allocate mem for reply string */
	reply = malloc(8);
	if (!reply)
		goto err_close_cfd; /* ignore call: insufficient memory */

	/* argument parsing */
	argc = 1;
	argv[0] = ""; /* no command name since we get called by a trigger */
	prev_was_whitespace = 1;
	for (i = 0; argc < SHWRAPPER_MAX_NB_ARGS; ++i) {
		switch (argb[i]) {
		case '\0': /* end of string */
			goto exec;
			break;
		case ' ': /* white spaces */
		case '\r':
		case '\n':
		case '\t':
		case '\v':
			argb[i] = '\0';
			prev_was_whitespace = 1;
            break;
		case '\'': /* quotes */
		case '"':
			/* QUOTES NOT SUPPORTED YET (like µSh) */
		default:
			if (prev_was_whitespace) {
				argv[argc++] = &argb[i];
				prev_was_whitespace = 0;
			}
			break;
		}
	}

 exec:
	/* execute command */
	ret = shcmd(cio, argc, argv);
	snprintf(reply, 8, "%d", ret);
	fclose(cio); /* closes also cfd */
	return reply;

 err_close_cfd:
	close(cfd);
 err_out:
	return NULL;
}

int ctldir_register_shcmd(struct ctldir *cd, const char *name, shfunc_ptr_t func)
{
	return ctldir_register_trigger(cd, name, _shcmd_wrapper, (void *) func);
}

/*
 * Create entries on xenstore and start watcher thread
 */
int ctldir_start_watcher(struct ctldir *cd)
{
	xenbus_transaction_t xbt;
	char path[(2 * CTLDIR_MAX_NAMELEN) + 8];
	char token[9];
	register uint32_t i;
	register int ret;
	register int err = -EACCES;
	domid_t self;

	BUG_ON(cd->watcher != NULL);

	self = xenbus_get_self_id();
	for (;;) {
		ret = _xb_begin_transaction(&xbt);
		if (ret < 0)
			goto err_out;

		/* base/lock = "0" */
		snprintf(path, sizeof(path), "%s/%s", cd->basename, cd->lock_name);
		ret = _xb_write(xbt, path, "0");
		if (ret < 0)
			goto err_abort_xbt;

		for (i = 0; i < cd->nb_trigger; ++i) {
			/* base/trigger-in = "" */
			ret = _xb_write(xbt, cd->trigger_ipath[i], "");
			if (ret < 0)
				goto err_abort_xbt;
			/* base/trigger-out = "" */
			ret = _xb_write(xbt, cd->trigger_opath[i], "");
			if (ret < 0)
				goto err_abort_xbt;
			/* base/feature-trigger = "1" */
			snprintf(path, sizeof(path), "%s/feature-%s", cd->basename, cd->trigger_name[i]);
			ret = _xb_write(xbt, path, "1");
			if (ret < 0)
				goto err_abort_xbt;
			cd->trigger_ignore[i] = 1; /* ignore entry creation */
		}

		ret = _xb_submit_transaction(xbt);
		if (ret == -EINTR)
			continue; /* retry */
		if (ret < 0)
			goto err_out; /* error happened */
		break; /* done */
	}

#ifndef CTLDIR_NOCHMOD
	/* set permissions (ignore errors) */
	/* base/lock */
	snprintf(path, sizeof(path), "%s/%s", cd->basename, cd->lock_name);
	_xb_chmod(path, DOM0, 'b');
	_xb_chmod(path, self, 'n');
	for (i = 0; i < cd->nb_trigger; ++i) {
		/* base/feature */
		_xb_chmod(cd->trigger_ipath[i], DOM0, 'w');
		_xb_chmod(cd->trigger_ipath[i], self, 'r');
		_xb_chmod(cd->trigger_opath[i], DOM0, 'w');
		_xb_chmod(cd->trigger_opath[i], self, 'r');
		/* base/feature-trigger */
		snprintf(path, sizeof(path), "%s/feature-%s", cd->basename, cd->trigger_name[i]);
		_xb_chmod(path, DOM0, 'r');
		_xb_chmod(path, self, 'n');
	}
#endif /* CTLDIR_NOCHMOD */

	/* setup watches */
	for (i = 0; i < cd->nb_trigger; ++i) {
		/* use index as token (4 byte hex number) */
		snprintf(token, sizeof(token), "%08x", i);
		ret = _xb_watch_token(cd->trigger_ipath[i],
		                      token, &cd->xseq);
		if (ret < 0) {
			printk("FATAL: Could not setup watch");
			goto err_unwatch;
		}
	}

	/* create thread only if there are triggers */
	if (cd->nb_trigger) {
		cd->watcher = create_thread(cd->threadname, ctldir_watcherthread, cd);
		if (!cd->watcher) {
			err = -ENOMEM;
			goto err_unwatch;
		}
	}

	return 0;

 err_unwatch:
	for (i = 0; i < cd->nb_trigger; ++i) {
		snprintf(token, sizeof(token), "%08x", i);
		_xb_unwatch_token(cd->trigger_ipath[i], token);
	}

	snprintf(path, sizeof(path), "%s/%s", cd->basename, cd->lock_name);
	_xb_rm(path);
	for (i = 0; i < cd->nb_trigger; ++i) {
		/* base/trigger-[in/out] */
		_xb_rm(cd->trigger_ipath[i]);
		_xb_rm(cd->trigger_opath[i]);
		/* base/feature-trigger */
		snprintf(path, sizeof(path), "%s/feature-%s", cd->basename, cd->trigger_name[i]);
		_xb_rm(path);
	}
	goto err_out;

 err_abort_xbt:
	_xb_abort_transaction(xbt);
 err_out:
	return err;
}

/*
 * Watcher thread
 */
static void ctldir_watcherthread(void *argp) {
	struct ctldir *cd = (struct ctldir *) argp;
	struct xenbus_event *xse;
	register int ret;
	char *arg;
	char *reply;
	uint32_t i;

	/* wait for events */
	for (;;) {
		xse = xenbus_wait_for_watch_return_event(&cd->xseq);

		if (unlikely(!xse->path || !xse->token))
			continue; /* invalid event element */
		if (unlikely(sscanf(xse->token, "%08x", &i) != 1))
			continue; /* token could not be parsed */
		if (unlikely(i > cd->nb_trigger))
			continue; /* token is out of range */
		if (unlikely(strcmp(xse->path, cd->trigger_ipath[i]) != 0))
			continue; /* invalid token */
		if (unlikely(cd->trigger_ignore[i])) {
			--cd->trigger_ignore[i];
			continue; /* ignore was set */
		}
		if (!cd->trigger_func[i])
			continue; /* no callback specified */

		ret = _xb_read(XBT_NIL, cd->trigger_ipath[i], &arg);
		if (ret < 0 || !arg)
			continue; /* read error */

		reply = cd->trigger_func[i](cd->trigger_cookie[i], arg);
		free(arg);
		if (reply) {
			_xb_write(XBT_NIL, cd->trigger_opath[i], reply);
			free(reply);
		} else {
			_xb_write(XBT_NIL, cd->trigger_opath[i], "");
		}
	}
}
