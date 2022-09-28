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
 */
#include <mini-os/os.h>
#include <mini-os/xenbus.h>
#include <mini-os/xmalloc.h>
#include <mini-os/wait.h>
#include <mini-os/sched.h>
#include <mini-os/lib.h>
#include <fcntl.h>
#include <unistd.h>
#include <target/ctldir.h>

#ifdef CTLDIR_DEBUG
#define ENABLE_DEBUG
#endif
#include "debug.h"

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
	__xb_errmsg ? -EINVAL: 0; })
#define _xb_read(xbt, path, value_ptr) ({ \
	char *__xb_errmsg; \
	__xb_errmsg = xenbus_read((xbt), (path), (value_ptr)); \
	if (__xb_errmsg) { \
		printk("%s:%u: xenbus_read(%s) failed: %s\n", \
		       __FILE__, __LINE__, (path), __xb_errmsg); \
		free(__xb_errmsg); \
	} \
	__xb_errmsg ? -EINVAL: 0; })
#ifndef CTLDIR_NOCHMOD
#define _xb_chmod(xbt, path, domid, domperm) ({	\
	char *__xb_errmsg; \
	__xb_errmsg = xenbus_set_perms((xbt), (path), (domid), (domperm)); \
	if (__xb_errmsg) { \
		printk("%s:%u: xenbus_set_perms(%s) failed: %s\n",  \
		       __FILE__, __LINE__, (path), __xb_errmsg); \
		free(__xb_errmsg); \
	} \
	__xb_errmsg ? -EINVAL: 0; })
#endif /* CTLDIR_NOCHMOD */
#define _xb_rm(xbt, path) ({ \
	char *__xb_errmsg; \
	__xb_errmsg = xenbus_rm((xbt), (path)); \
	if (__xb_errmsg) { \
		printk("%s:%u: xenbus_set_perms(%s) failed: %s\n", \
		       __FILE__, __LINE__, (path), __xb_errmsg); \
		free(__xb_errmsg); \
	} \
	__xb_errmsg ? -EINVAL: 0; })
#define _xb_transaction_start(xbt_ptr) ({ \
	char *__xb_errmsg; \
	__xb_errmsg = xenbus_transaction_start((xbt_ptr)); \
	if (__xb_errmsg) { \
		printk("%s:%u: xenbus_transaction_start(%p) failed: %s\n", \
		       __FILE__, __LINE__, (xbt_ptr), __xb_errmsg); \
		free(__xb_errmsg); \
	} \
	__xb_errmsg ? -EINVAL: 0; })
#define _xb_transaction_end(xbt, abort) ({		\
	char *__xb_errmsg; \
	int __xb_retry = 0; \
	__xb_errmsg = xenbus_transaction_end((xbt), (abort), &__xb_retry); \
	if (__xb_errmsg) { \
		printk("%s:%u: xenbus_transaction_end(%p) failed: %s\n", \
		       __FILE__, __LINE__, &(xbt), __xb_errmsg); \
		free(__xb_errmsg); \
	} \
	__xb_retry ? -EAGAIN : (__xb_errmsg ? -EINVAL : 0); })
#define _xb_watch_token(path, token, xseq) ({ \
	char *__xb_errmsg; \
	__xb_errmsg = xenbus_watch_path_token(XBT_NIL, (path), (token), (xseq)); \
	if (__xb_errmsg) { \
		printk("%s:%u: xenbus_watch_path_token(%s:%s) failed: %s\n", \
		       __FILE__, __LINE__, (path), (token), __xb_errmsg); \
		free(__xb_errmsg); \
	} \
	__xb_errmsg ? -EINVAL: 0; })

#define _xb_unwatch_token(path, token) ({ \
	char *__xb_errmsg; \
	__xb_errmsg = xenbus_unwatch_path_token(XBT_NIL, (path), (token)); \
	if (__xb_errmsg) { \
		printk("%s:%u: xenbus_watch_unpath_token(%s:%s) failed: %s\n", \
		       __FILE__, __LINE__, (path), (token), __xb_errmsg); \
		free(__xb_errmsg); \
	} \
	__xb_errmsg ? -EINVAL: 0; })

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
	const char *dataname = "data";
	struct ctldir *ctld;
	int ret;

	ctld = _xmalloc(sizeof(*ctld), 1);
	if (!ctld) {
		errno = ENOMEM;
		goto err_out;
	}

	snprintf(ctld->basename, sizeof(ctld->basename), "%s/%s", dataname, name);
	snprintf(ctld->threadname, sizeof(ctld->threadname), "ctlwatch-%s", name);
	ctld->watcher = NULL;
	ctld->lock_name = "lock";
	ctld->nb_trigger = 0;
	ctld->xseq = NULL;

	/* check if data dir is writable */
	ret = _xb_write(XBT_NIL, dataname, "");
	if (ret < 0) {
		errno = EACCES;
		goto err_free_ctld;
	}

	/* create base dir or check if it is writable */
	ret = _xb_write(XBT_NIL, ctld->basename, "");
	if (ret < 0) {
		errno = EACCES;
		goto err_free_ctld;
	}

	return ctld;

 err_free_ctld:
	free(ctld);
 err_out:
	return NULL;
}

int ctldir_register_trigger(struct ctldir *ctld, const char *name, ctldfunc_ptr_t func, void *cookie)
{
	register uint32_t i = ctld->nb_trigger;
	size_t len;

	BUG_ON(ctld->watcher != NULL);

	if (i >= CTLDIR_MAX_TRIGGERS)
		return -ENOSPC;

	ctld->trigger_name[i] = strndup(name, CTLDIR_MAX_NAMELEN);
	if (!ctld->trigger_name[i])
		goto err_out;

	len = strlen(name) + strlen(ctld->basename) + 2 + 3;
	ctld->trigger_ipath[i] = malloc(len);
	if (!ctld->trigger_ipath[i])
		goto err_free_name;
	snprintf(ctld->trigger_ipath[i], len,
	         "%s/%s-in", ctld->basename, ctld->trigger_name[i]);

	len = strlen(name) + strlen(ctld->basename) + 2 + 4;
	ctld->trigger_opath[i] = malloc(len);
	if (!ctld->trigger_opath[i])
		goto err_free_ipath;
	snprintf(ctld->trigger_opath[i], len,
	         "%s/%s-out", ctld->basename, ctld->trigger_name[i]);

	ctld->trigger_func[i] = func;
	ctld->trigger_cookie[i] = cookie;
	++ctld->nb_trigger;

	return 0;

 err_free_ipath:
	free(ctld->trigger_ipath[i]);
 err_free_name:
	free(ctld->trigger_name[i]);
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
	argv[0] = &argb[i]; /* use last terminating zero as command name
			     * --> no command name since we get called by a trigger */

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

int ctldir_register_shcmd(struct ctldir *ctld, const char *name, shfunc_ptr_t func)
{
	return ctldir_register_trigger(ctld, name, _shcmd_wrapper, (void *) func);
}

/*
 * Create entries on xenstore and start watcher thread
 */
int ctldir_start_watcher(struct ctldir *ctld)
{
	xenbus_transaction_t xbt;
	char path[(2 * CTLDIR_MAX_NAMELEN) + 8];
	char token[9];
	register uint32_t i;
	register int ret;
	register int err = -EACCES;
#ifndef CTLDIR_NOCHMOD
	domid_t self = xenbus_get_self_id();
#endif
	BUG_ON(ctld->watcher != NULL);

 retry_mkctldir:
	ret = _xb_transaction_start(&xbt);
	if (ret < 0)
		goto err_out;

	/* base/lock = "0" */
	snprintf(path, sizeof(path), "%s/%s", ctld->basename, ctld->lock_name);
	ret = _xb_write(xbt, path, "0");
	if (ret < 0)
		goto err_abort_xbt;

	for (i = 0; i < ctld->nb_trigger; ++i) {
		/* base/trigger-in = "" */
		ret = _xb_write(xbt, ctld->trigger_ipath[i], "");
		if (ret < 0)
			goto err_abort_xbt;
		/* base/trigger-out = "" */
		ret = _xb_write(xbt, ctld->trigger_opath[i], "");
		if (ret < 0)
			goto err_abort_xbt;
		/* base/feature-trigger = "1" */
		snprintf(path, sizeof(path), "%s/feature-%s", ctld->basename, ctld->trigger_name[i]);
		ret = _xb_write(xbt, path, "1");
		if (ret < 0)
			goto err_abort_xbt;
		ctld->trigger_ignore[i] = 1; /* ignore entry creation */
	}

	ret = _xb_transaction_end(xbt, 0);
	if (ret == -EAGAIN)
		goto retry_mkctldir;
	if (ret < 0)
		goto err_out; /* error happened */

#ifndef CTLDIR_NOCHMOD
	/* set permissions (ignore errors) */
	/* base/lock */
	snprintf(path, sizeof(path), "%s/%s", ctld->basename, ctld->lock_name);
 retry_chmod:
	ret = _xb_transaction_start(&xbt);
	if (ret < 0)
		goto err_out;
	_xb_chmod(xbt, path, DOM0, 'b');
	_xb_chmod(xbt, path, self, 'n');
	for (i = 0; i < ctld->nb_trigger; ++i) {
		/* base/feature */
		_xb_chmod(xbt, ctld->trigger_ipath[i], DOM0, 'w');
		_xb_chmod(xbt, ctld->trigger_ipath[i], self, 'r');
		_xb_chmod(xbt, ctld->trigger_opath[i], DOM0, 'r');
		_xb_chmod(xbt, ctld->trigger_opath[i], self, 'w');
		/* base/feature-trigger */
		snprintf(path, sizeof(path), "%s/feature-%s", ctld->basename, ctld->trigger_name[i]);
		_xb_chmod(xbt, path, DOM0, 'r');
		_xb_chmod(xbt, path, self, 'n');
	}
	ret = _xb_transaction_end(xbt);
	if (ret == -EAGAIN)
		goto retry_chmod;
	if (ret < 0)
		goto err_out; /* error happened */
#endif /* CTLDIR_NOCHMOD */

	/* setup watches */
	for (i = 0; i < ctld->nb_trigger; ++i) {
		/* use index as token (4 byte hex number) */
		snprintf(token, sizeof(token), "%08x", i);
		ret = _xb_watch_token(ctld->trigger_ipath[i],
		                      token, &ctld->xseq);
		if (ret < 0) {
			printd("FATAL: Could not setup watch");
			goto err_unwatch;
		}
	}

	/* create thread only if there are triggers */
	if (ctld->nb_trigger) {
		ctld->watcher = create_thread(ctld->threadname, ctldir_watcherthread, ctld);
		if (!ctld->watcher) {
			err = -ENOMEM;
			goto err_unwatch;
		}
	}

	return 0;

 err_unwatch:
	for (i = 0; i < ctld->nb_trigger; ++i) {
		snprintf(token, sizeof(token), "%08x", i);
		_xb_unwatch_token(ctld->trigger_ipath[i], token);
	}

	snprintf(path, sizeof(path), "%s/%s", ctld->basename, ctld->lock_name);
	_xb_rm(XBT_NIL, path);
	for (i = 0; i < ctld->nb_trigger; ++i) {
		/* base/trigger-[in/out] */
		_xb_rm(XBT_NIL, ctld->trigger_ipath[i]);
		_xb_rm(XBT_NIL, ctld->trigger_opath[i]);
		/* base/feature-trigger */
		snprintf(path, sizeof(path), "%s/feature-%s", ctld->basename, ctld->trigger_name[i]);
		_xb_rm(XBT_NIL, path);
	}
	goto err_out;

 err_abort_xbt:
	_xb_transaction_end(xbt, 1);
 err_out:
	return err;
}

/*
 * Watcher thread
 */
static void ctldir_watcherthread(void *argp) {
	struct ctldir *ctld = (struct ctldir *) argp;
	struct xenbus_event *xse;
	xenbus_transaction_t xbt;
	register int ret, rret;
	char *arg;
	char *reply;
	uint32_t i;

	/* wait for events */
	for (;;) {
		xse = xenbus_wait_for_watch_return_event(&ctld->xseq);
		printd("Wake up from XenBus watch\n");

		if (unlikely(!xse->path || !xse->token))
			continue; /* invalid event element */
		if (unlikely(sscanf(xse->token, "%08x", &i) != 1))
			continue; /* token could not be parsed */
		if (unlikely(i > ctld->nb_trigger))
			continue; /* token is out of range */
		if (unlikely(strcmp(xse->path, ctld->trigger_ipath[i]) != 0))
			continue; /* invalid token */
		if (unlikely(ctld->trigger_ignore[i])) {
			--ctld->trigger_ignore[i];
			printd("Ignore event for trigger %s\n", ctld->trigger_ipath[i]);
			continue; /* ignore was set */
		}

	retry_read:
		printd("Initialize transaction for read: %d\n", ret);
		ret = _xb_transaction_start(&xbt);
		if (ret < 0) {
			printd("Fatal transaction error on read: %d\n", ret);
			continue; /* transaction error */
		}
		printd("Read from %s\n", ctld->trigger_ipath[i]);
		rret = _xb_read(xbt, ctld->trigger_ipath[i], &arg);
		printd("Finalize transaction for read: %d\n", ret);
		ret = _xb_transaction_end(xbt, 0);
		if (ret == -EAGAIN) {
			printd("Retry read transaction\n");
			goto retry_read;
		}
		if (ret < 0) {
			printd("Fatal transaction error on read: %d\n", ret);
			continue; /* error happened */
		}
		if (rret < 0 || !arg)
			continue; /* read error */

		printd("Calling callback %p...\n", ctld->trigger_func[i]);
		reply = ctld->trigger_func[i] ?
		        ctld->trigger_func[i](ctld->trigger_cookie[i], arg) : NULL;
		printd("Callback returned: '%s'\n", reply);
		free(arg);

	retry_write:
		printd("Initialize transaction for write: %d\n", ret);
		ret = _xb_transaction_start(&xbt);
		if (ret < 0) {
			printd("Fatal transaction error on write: %d\n", ret);
			continue; /* transaction error */
		}
		printd("Write to %s\n", ctld->trigger_opath[i]);
		_xb_write(xbt, ctld->trigger_opath[i], reply ? reply : "");
		printd("Finalize transaction for write: %d\n", ret);
		ret = _xb_transaction_end(xbt, 0);
		if (ret == -EAGAIN) {
			printd("Retry write transaction\n");
			goto retry_write;
		}
		if (ret < 0) {
			printd("Fatal transaction error on write: %d\n", ret);
			continue; /* error happened */
		}

		if (reply)
			free(reply);
	}
}
