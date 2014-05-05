/*
 * MicroShell (µSh) for Mini-OS
 *
 * Copyright(C) 2013-2014 NEC Laboratories Europe. All rights reserved.
 *                        Simon Kuenzer <simon.kuenzer@neclab.eu>
 */
#include <mini-os/os.h>
#include <mini-os/types.h>
#include <mini-os/xmalloc.h>
#include <mini-os/wait.h>
#include <kernel.h>
#include <errno.h>
#include <sched.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>

#ifdef SHELL_DEBUG
#define ENABLE_DEBUG
#endif
#include "debug.h"

#ifdef HAVE_LWIP
#include <lwip/tcp.h>
#endif

#include "shell.h"

#define MAX_NB_CMDS 64
#define MAX_NB_ARGS 96
#define ARGB_LEN 256
#define MAX_NB_SESS 8
#ifdef HAVE_LWIP
#define SH_RXBUFLEN 2048 /* input buffer size for TCP: has to be a power of 2! */
#define SH_RXBUFMASK (SH_RXBUFLEN - 1)
#define SH_TCP_PRIO TCP_PRIO_MIN
#define SH_LISTEN_PORT 23 /* telnet */
#define SH_TCPKEEPALIVE_TIMEOUT 120 /* = x sec */
#define SH_TCPKEEPALIVE_IDLE    60 /* = x sec */

#endif

#define SESSNAME_MAXLEN 16
#define SESSNAME_LFMT "lsh%u"
#ifdef HAVE_LWIP
#define SESSNAME_RFMT "rsh%u"
#endif

#ifndef SHELL_INFO
#define SHELL_INFO "µShell - A minimalistic CLI\nCopyright 2013-2014 NEC Laboratories Europe Ltd."
#endif
#ifndef SHELL_WELCOME
#define SHELL_WELCOME SHELL_INFO"\nWelcome to Mini-OS!"
#endif
#ifndef SHELL_GOODBYE
#define SHELL_GOODBYE "logout"
#endif
#ifndef SHELL_PROMPT
#define SHELL_PROMPT "µsh#"
#endif


#ifndef min
#define min(a, b) \
    ({ __typeof__ (a) __a = (a); \
       __typeof__ (b) __b = (b); \
       __a < __b ? __a : __b; })
#endif

struct shell {
    struct tcp_pcb *tpcb;
    struct timeval ts_start;
    const char *info;
    const char *welcome;
    const char *goodbye;

    /* commands register */
    const char *cmd_str[MAX_NB_CMDS];
    shfunc_ptr_t cmd_func[MAX_NB_CMDS];

    /* shell sessions */
    uint32_t nb_sess;
    uint32_t max_nb_sess;
    struct shell_sess *sess[MAX_NB_SESS];
};

enum shell_sess_state
{
    SSS_NONE = 0,
    SSS_ESTABLISHED,
    SSS_CLOSING,
    SSS_KILLING
};

enum shell_sess_type
{
    SST_LOCAL = 0,
#ifdef HAVE_LWIP
    SST_REMOTE,
#endif
};

struct shell_sess {
    /* session settings */
    uint32_t id;
    char name[SESSNAME_MAXLEN];
    enum shell_sess_type type;
    enum shell_sess_state state;

    struct timeval ts_start;
    char *prompt;
    int echo; /* echo input */
    int respawn; /* respawn a closed session? */

    /* session thread */
    struct thread *thread;

    /* console i/o */
    char argb[ARGB_LEN]; /* argument buffer */
    FILE *cio; /* stdin/stdout of session */

    int cons_fd; /* serial console on SSS_LOCAL */
#ifdef HAVE_LWIP
    struct tcp_pcb *tpcb; /* TCP PCB */
    /* rx buffer (tcp session) */
    char cio_rxbuf[SH_RXBUFLEN];
    uint16_t cio_rxbuf_ridx;
    uint16_t cio_rxbuf_widx;
#endif

};

static struct shell *sh = NULL; /* will be initialized first */

static int shcmd_info(FILE *cio, int argc, char *argv[]);
static int shcmd_help(FILE *cio, int argc, char *argv[]);
static int shcmd_echo(FILE *cio, int argc, char *argv[]);
static int shcmd_clear(FILE *cio, int argc, char *argv[]);
static int shcmd_time(FILE *cio, int argc, char *argv[]);
static int shcmd_repeat(FILE *cio, int argc, char *argv[]);
static int shcmd_uptime(FILE *cio, int argc, char *argv[]);
static int shcmd_date(FILE *cio, int argc, char *argv[]);
static int shcmd_who(FILE *cio, int argc, char *argv[]);
static int shcmd_exit(FILE *cio, int argc, char *argv[]);
#ifdef SHELL_DEBUG
static int shcmd_args(FILE *cio, int argc, char *argv[]);
#endif

static err_t shlsess_accept(void);
static void  shlsess_close (struct shell_sess *sess);

#ifdef HAVE_LWIP
static err_t shrsess_accept(void *argp, struct tcp_pcb *new_tpcb, err_t err);
static void  shrsess_close (struct shell_sess *sess);
static err_t shrsess_recv  (void *argp, struct tcp_pcb *tpcb, struct pbuf *p, err_t err);
static void  shrsess_error (void *argp, err_t err);
static err_t shrsess_poll  (void *argp, struct tcp_pcb *tpcb);
#endif

int init_shell(unsigned int en_lsess, unsigned int nb_rsess)
{
    int32_t i;
    err_t err;

    sh = _xmalloc(sizeof(*sh), PAGE_SIZE);
    if (!sh) {
        errno = ENOMEM;
        goto err_out;
    }

    gettimeofday(&sh->ts_start, NULL); /* timestamp of shell creation */
    sh->welcome = SHELL_WELCOME;
    sh->goodbye = SHELL_GOODBYE;
    for (i = 0; i < MAX_NB_CMDS; i++) {
        sh->cmd_str[i] = NULL;
        sh->cmd_func[i] = NULL;
    }
    for (i = 0; i < MAX_NB_SESS; i++) {
        sh->sess[i] = NULL;
    }
    sh->max_nb_sess = min(nb_rsess + (en_lsess ? 1 : 0), MAX_NB_SESS);
    sh->nb_sess = 0;

    /* register TCP listener */
#ifdef HAVE_LWIP
    if (nb_rsess) {
        sh->tpcb = tcp_new();
        if (!sh->tpcb) {
            errno = ENOMEM;
            goto err_free_sh;
        }
        err = tcp_bind(sh->tpcb, IP_ADDR_ANY, SH_LISTEN_PORT);
        if (err != ERR_OK) {
            errno = ENOMEM;
            goto err_free_tcp;
        }
        sh->tpcb = tcp_listen(sh->tpcb);
        tcp_arg(sh->tpcb, sh);
        tcp_accept(sh->tpcb, shrsess_accept); /* register session accept */
    } else {
        sh->tpcb = NULL;
    }
#endif

    /* register default commands (ignore errors) */
    shell_register_cmd("help",   shcmd_help);
    shell_register_cmd("info",   shcmd_info);
    shell_register_cmd("exit",   shcmd_exit);
    shell_register_cmd("clear",  shcmd_clear);
    shell_register_cmd("echo",   shcmd_echo);
    shell_register_cmd("who",    shcmd_who);
    shell_register_cmd("time",   shcmd_time);
    shell_register_cmd("repeat", shcmd_repeat);
    shell_register_cmd("uptime", shcmd_uptime);
    shell_register_cmd("date",   shcmd_date);
#ifdef SHELL_DEBUG
    shell_register_cmd("args",   shcmd_args);
#endif
    /* create a local shell session on stdin/stdout */
    if (en_lsess)
        shlsess_accept();
    return 0;

#ifdef HAVE_LWIP
err_free_tcp:
    if (nb_rsess)
        tcp_close(sh->tpcb);
#endif
err_free_sh:
    xfree(sh);
err_out:
    return -1;
}

void exit_shell(void)
{
    uint32_t i;
    int wait;

#ifdef HAVE_LWIP
    /* disable tcp listener */
    if (sh->tpcb)
        tcp_accept(sh->tpcb, NULL);
#endif

    /* close all opened sessions and wait for their exit */
    do {
        wait = 0;
        for (i = 0; i < MAX_NB_SESS; i++) {
            if (sh->sess[i]) {
                sh->sess[i]->state = SSS_CLOSING;
                wait = 1;
            }
        }
        schedule();
    } while (wait);

#ifdef HAVE_LWIP
    if (sh->tpcb)
        tcp_close(sh->tpcb);
#endif
    xfree(sh);
}

static int32_t shell_get_free_sess_id(void)
{
    int32_t i = 0;
    while (sh->sess[i] && i < sh->max_nb_sess)
        i++;

    if (i == sh->max_nb_sess)
        return -1; /* no session id available */
    return i;
}

/* --------------------------------------
 * Command handling
 * -------------------------------------- */
static int32_t shell_get_cmd_index(const char *cmd)
{
    int32_t i;

    for (i = 0; i < MAX_NB_CMDS; i++) {
        if (sh->cmd_str[i]) {
            if (strcmp(sh->cmd_str[i], cmd) == 0)
                return i; /* found */
        }
    }
    errno = ENOENT;
    return -1; /* not found */
}

int shell_register_cmd(const char *cmd, shfunc_ptr_t func)
{
    uint32_t i;

    BUG_ON(sh == NULL);

    /* search for cmd */
    if (!shell_get_cmd_index(cmd) < 0) {
        /* cmd already registered */
        errno = EEXIST;
        return -1;
    }

    /* search for a free slot */
    for (i = 0; i < MAX_NB_CMDS; i++) {
        if (!sh->cmd_str[i])
            break; /* found a slot */
    }
    if (i == MAX_NB_CMDS) {
        /* no slot found for cmd */
        errno = ENOSPC;
        return -1;
    }

    /* register cmd */
    sh->cmd_func[i] = func;
    sh->cmd_str[i] = cmd;
    dprintf("shell: Command %i ('%s') registered (func=@%p)\n", i, cmd, func);
    return 0;
}

void shell_unregister_cmd(const char *cmd)
{
    int32_t i;

    BUG_ON(sh == NULL);

    i = shell_get_cmd_index(cmd);
    if (i >= 0) {
        sh->cmd_func[i] = NULL;
        sh->cmd_str[i] = NULL;
        dprintf("shell: Command %i ('%s') unregistered\n", i, cmd);
    }
}

static int sh_exec(FILE *cio, char *argb, size_t argb_len)
{
    char *argv[MAX_NB_ARGS];
    int argc;
    int ret;
    size_t i;
    int32_t cmdi;
    int prev_was_whitespace;

    /* parse argument line (fillup argv) */
    argc = 0;
    prev_was_whitespace = 1;
    for (i = 0; i < argb_len && argc < MAX_NB_ARGS; i++) {
        switch (argb[i]) {
        case '\0': /* end of string */
            goto out;
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
            /* QUOTES NOT SUPPORTED YET */
        default:
            if (prev_was_whitespace) {
                argv[argc++] = &argb[i];
                prev_was_whitespace = 0;
            }
            break;
        }
    }

 out:
    if (argc == 0)
        return 0; /* nothing was typed */

    cmdi = shell_get_cmd_index(argv[0]);
    if (cmdi < 0) {
        fprintf(cio, "%s: command not found\n", argv[0]);
        return 0;
    }

    ret = sh->cmd_func[cmdi](cio, argc, argv);
    if (ret < 0)
        fprintf(cio, "%s: command returned %d\n", argv[0], ret);

    return ret;
}

/* the shell session thread */
static void sh_session(void *argp)
{
    struct shell_sess *sess = argp;
    size_t argb_p;
    int ret;

respawn:
    if (sh->welcome)
        fprintf(sess->cio, "\n%s\n", sh->welcome);

    while (1)
    {
        /* print prompt */
        if (sess->prompt)
            fprintf(sess->cio, "%s ", sess->prompt);
        fflush(sess->cio);

        /* read sess->argb from cio */
        argb_p = 0;
        while (argb_p < sizeof(sess->argb) - 1) {
            if (sess->state == SSS_CLOSING ||
                sess->state == SSS_KILLING)
                goto terminate;
            ret = fgetc(sess->cio);
            if (ret == EOF)
	        goto terminate;
            sess->argb[argb_p] = (char) ret;
            if (sess->state == SSS_CLOSING ||
                sess->state == SSS_KILLING)
                goto terminate;

            switch (sess->argb[argb_p]) {
            case 0x0a: /* new line \n */
            case 0x0d: /* enter \r */
                goto exec_cmd;
            case 0x7f: /* delete */
                sess->argb[argb_p] = '\0';
                if (argb_p > 0) {
                    argb_p--;
                    /* print destructive backspace */
                    if (sess->echo) {
                        fprintf(sess->cio, "%s", "\b \b");
                        fflush(sess->cio);
                    }
                }
                break;
            case 0x20 ... 0x7e: /* ASCII chars */
                if (sess->echo) {
                    fprintf(sess->cio, "%c", sess->argb[argb_p]);
                    fflush(sess->cio);
                }
                argb_p++;
                break;
            default:
                break; /* ignore rest of characters */
            }
        }

    exec_cmd:
        if (sess->echo)
            fprintf(sess->cio, "\n");

        ret = sh_exec(sess->cio, sess->argb, argb_p + 1);
        fflush(sess->cio);
        if (ret == SH_CLOSE) {
	    sess->state = SSS_CLOSING;
            break;
        }
    }
    if (sh->goodbye)
        fprintf(sess->cio, "%s\n", sh->goodbye);
    fflush(sess->cio);

    if (sess->respawn)
        goto respawn;

terminate:
#ifdef HAVE_LWIP
    if (sess->type == SST_REMOTE)
	    shrsess_close(sess);
    else
#endif
	    shlsess_close(sess);
}


/* --------------------------------------
 * Local session handling
 * -------------------------------------- */
static err_t shlsess_accept(void)
{
    struct shell_sess *sess;
    err_t err;

    if (sh->nb_sess == sh->max_nb_sess) {
        err = ERR_MEM;
        goto err_out;
    }
    sess = _xmalloc(sizeof(*sess), PAGE_SIZE);
    if (!sess) {
        err = ERR_MEM;
        goto err_out;
    }

    sess->cons_fd = open("/var/log/", O_RDWR); /* workaround to
                                                * access stdin/stdout */
    if (sess->cons_fd < 0) {
        err = ERR_ABRT;
        goto err_free_sess;
    }
    sess->cio = fdopen(sess->cons_fd, "r+");

    sess->tpcb = NULL;
    sess->type = SST_LOCAL;
    sess->state = SSS_NONE;
    sess->echo = 1; /* enable echo of input on console */
    sess->respawn = 1; /* enable session respawning */

    gettimeofday(&sess->ts_start, NULL);
    sess->prompt = strdup(SHELL_PROMPT);
    if (!sess->prompt) {
        err = ERR_MEM;
        goto err_close_cons;
    }
    sess->id = shell_get_free_sess_id();

    snprintf(sess->name, SESSNAME_MAXLEN, SESSNAME_LFMT, sess->id);
    sess->thread = create_thread(sess->name, sh_session, sess);
    if (!sess->thread) {
        err = ERR_MEM;
        goto err_free_prompt;
    }
    sh->sess[sess->id] = sess; /* register session */
    sh->nb_sess++;
    dprintf("shell: Local session opened (%s)\n", sess->name);
    return ERR_OK;

err_free_prompt:
    xfree(sess->prompt);
err_close_cons:
    close(sess->cons_fd);
err_free_sess:
    xfree(sess);
err_out:
    return err;
}

static void shlsess_close(struct shell_sess *sess)
{
    BUG_ON(sess->type != SST_LOCAL);

    /* unregister session */
    sh->sess[sess->id]=NULL;
    sh->nb_sess--;

    xfree(sess->prompt);

    /* close console descriptor */
    fclose(sess->cio);

    dprintf("shell: Local session closed (%s)\n", sess->name);
    xfree(sess);
}


/* --------------------------------------
 * Remote session handling
 * -------------------------------------- */
#ifdef HAVE_LWIP
#define RXBUF_NB_AVAIL(s) ((SH_RXBUFLEN  + (s)->cio_rxbuf_widx - (s)->cio_rxbuf_ridx) & SH_RXBUFMASK)
#define RXBUF_NB_FREE(s)  ((SH_RXBUFMASK + (s)->cio_rxbuf_ridx - (s)->cio_rxbuf_widx) & SH_RXBUFMASK)

static ssize_t shrsess_cio_read(void *argp, char *buf, int maxlen)
{
    struct shell_sess *sess = argp;
    int i;
    int avail;

retry:
    if (sess->state == SSS_CLOSING || sess->state == SSS_KILLING)
        return EOF;

    avail = min(RXBUF_NB_AVAIL(sess), maxlen);
    if (!avail && maxlen) {
        /* we need to wait for further input of data */
        schedule(); /* TODO: use wait queue */
        goto retry;
    }
    for (i = 0; i < avail; i++) {
	buf[i] = sess->cio_rxbuf[sess->cio_rxbuf_ridx];
        sess->cio_rxbuf_ridx = (sess->cio_rxbuf_ridx + 1) & SH_RXBUFMASK;
    }
    /*
#ifdef SHELL_DEBUG
    dprintf("shell: Received %u bytes from client: '", avail);
    for (i = 0; i < avail; i++)
	    dprintf("%02x:", (unsigned char) buf[i]);
    dprintf("'\n");
#endif
    */
    return (ssize_t) avail;
}

static ssize_t shrsess_cio_write(void *argp, const char *buf, int len)
{
    struct shell_sess *sess = argp;
    err_t err = ERR_OK;
    int i = 0;
    uint16_t avail, sendlen;
    /*
#ifdef SHELL_DEBUG
    dprintf("shell: Sending %u bytes to client: '", len);
    for (i = 0; i < len; i++)
	dprintf("%c", buf[i]);
    dprintf("'\n");
    fflush(stdout);
    i = 0;
#endif
    */
    while (i < len) {
	    while((avail = tcp_sndbuf(sess->tpcb)) < 1) {
		    if (sess->state == SSS_CLOSING ||
		        sess->state == SSS_KILLING)
			    return (ssize_t) len;

		    /* flush tcp buffer and retry it later */
		    tcp_output(sess->tpcb);
		    schedule();

		    if (sess->state == SSS_CLOSING ||
		        sess->state == SSS_KILLING)
			    return (ssize_t) len;
	    }

	    sendlen = min(avail, (uint16_t) (len - i));
	    err = tcp_write(sess->tpcb, buf + i, sendlen, TCP_WRITE_FLAG_COPY);
	    if (err == ERR_MEM) {
		    /* retry later because of high memory pressure */
		    schedule();

		    if (sess->state == SSS_CLOSING ||
		        sess->state == SSS_KILLING)
			    return (ssize_t) len;
		    continue;
	    }
	    i += sendlen;
	    tcp_output(sess->tpcb);
    }

    return (ssize_t) len;
}

static err_t shrsess_accept(void *argp, struct tcp_pcb *new_tpcb, err_t err)
{
    struct shell_sess *sess;

    if (err != ERR_OK) {
        goto err_out;
    }
    if (sh->nb_sess == sh->max_nb_sess) {
        err = ERR_MEM;
        goto err_out;
    }
    sess = _xmalloc(sizeof(*sess), PAGE_SIZE);
    if (!sess) {
        err = ERR_MEM;
        goto err_out;
    }

    sess->tpcb = new_tpcb;
    sess->type = SST_REMOTE;
    sess->state = SSS_ESTABLISHED;
    sess->echo = 0; /* no echo of input on console */
    sess->respawn = 0; /* no session respawning */

    sess->prompt = strdup(SHELL_PROMPT);
    if (!sess->prompt) {
        err = ERR_MEM;
        goto err_free_sess;
    }
    gettimeofday(&sess->ts_start, NULL);
    sess->id = shell_get_free_sess_id();

    sess->cio_rxbuf_ridx = 0;
    sess->cio_rxbuf_widx = 0;
    sess->cio = funopen(sess,
                        shrsess_cio_read,
                        shrsess_cio_write,
                        NULL, NULL);
    if (!sess->cio) {
	err = ERR_MEM;
	goto err_free_prompt;
    }

    snprintf(sess->name, SESSNAME_MAXLEN, SESSNAME_RFMT, sess->id);
    sess->thread = create_thread(sess->name, sh_session, sess);
    if (!sess->thread) {
        err = ERR_MEM;
        goto err_free_prompt;
    }

    tcp_arg(sess->tpcb, sess); /* argp for callbacks */
    tcp_recv(sess->tpcb, shrsess_recv); /* recv callback */
    tcp_sent(sess->tpcb, NULL); /* sent ack callback */
    tcp_err(sess->tpcb, shrsess_error); /* err callback */
    tcp_poll(sess->tpcb, shrsess_poll, 0); /* poll callback */
    tcp_setprio(sess->tpcb, SH_TCP_PRIO);

    /* TCP keepalive */
    sess->tpcb->so_options |= SOF_KEEPALIVE;
    sess->tpcb->keep_intvl = (SH_TCPKEEPALIVE_TIMEOUT * 1000);
    sess->tpcb->keep_idle = (SH_TCPKEEPALIVE_IDLE * 1000);
    sess->tpcb->keep_cnt = 1;

    sh->sess[sess->id] = sess; /* register session */
    sh->nb_sess++;
    dprintf("shell: Remote session opened (%s)\n", sess->name);
    return ERR_OK;

err_free_prompt:
    xfree(sess->prompt);
err_free_sess:
    xfree(sess);
err_out:
    return err;
}

static void shrsess_close(struct shell_sess *sess)
{
    err_t err;

    BUG_ON(sess->type != SST_REMOTE);

    /* unregister session */
    sh->sess[sess->id]=NULL;
    sh->nb_sess--;

    xfree(sess->prompt);

    /* close console descriptor */
    fclose(sess->cio);

    /* disable tcp connection */
    tcp_arg(sess->tpcb, NULL);
    tcp_sent(sess->tpcb, NULL);
    tcp_recv(sess->tpcb, NULL);
    tcp_sent(sess->tpcb, NULL);
    tcp_err(sess->tpcb, NULL);
    tcp_poll(sess->tpcb, NULL, 0);

    /* terminate connection */
    if (sess->state != SSS_KILLING) {
	    err = tcp_close(sess->tpcb);
	    if (unlikely(err != ERR_OK))
		    tcp_abort(sess->tpcb);
    } /* on SSS_KILLING tpcb is not touched */

    /* release memory */
    dprintf("shell: Remote session closed (%s)\n", sess->name);
    xfree(sess);
}

static err_t shrsess_recv(void *argp, struct tcp_pcb *tpcb, struct pbuf *p, err_t err)
{
    struct shell_sess *sess = (struct shell_sess *) argp;
    struct pbuf *q;
    uint16_t i, j, r, rl;

    if (!p || err != ERR_OK) {
        if (p) {
            /* Inform TCP that we have taken the data */
            tcp_recved(sess->tpcb, p->tot_len);
            pbuf_free(p);
        }

        /* close connection */
        sess->state = SSS_CLOSING;
        return ERR_OK;
    }

    /* take the data (if receive buffer is too small: drop the rest) */
    rl = (uint16_t) min(p->tot_len, RXBUF_NB_FREE(sess));
    r = 0;
    for(q = p, i = 0; q != NULL && r < rl; i += q->len, q = q->next) {
        for (j = 0; j < q->len && r < rl; j++) {
            sess->cio_rxbuf[sess->cio_rxbuf_widx] = *(((char *) q->payload) + j);
            sess->cio_rxbuf_widx = (sess->cio_rxbuf_widx + 1) & SH_RXBUFMASK;
            r++;
        }
    }
    tcp_recved(sess->tpcb, p->tot_len);
    pbuf_free(p);
    schedule();

    return ERR_OK;
}

static void shrsess_error(void *argp, err_t err)
{
    struct shell_sess *sess = (struct shell_sess *) argp;
    sess->state = SSS_KILLING; /* kill connection on errors */
}

static err_t shrsess_poll(void *argp, struct tcp_pcb *tpcb)
{
    struct shell_sess *sess = (struct shell_sess *) argp;
    LWIP_UNUSED_ARG(sess);

    /* TODO */

    return ERR_OK;
}
#endif

/* --------------------------------------
 * Default commands
 * -------------------------------------- */
static int shcmd_info(FILE *cio, int argc, char *argv[])
{
    /* print session id and version */
    fprintf(cio, "%s\n", SHELL_INFO);
    return 0;
}

static int shcmd_help(FILE *cio, int argc, char *argv[])
{
    /* list available commands */
    int32_t i;

    for (i = 0; i < MAX_NB_CMDS; i++){
        if (sh->cmd_str[i])
            fprintf(cio, " %s\n", sh->cmd_str[i]);
    }
    return 0;
}

static int shcmd_who(FILE *cio, int argc, char *argv[])
{
    /* list opened sessions */
    struct timeval now;
    uint64_t days = 0;
    uint64_t hours = 0;
    uint64_t mins = 0;
    uint64_t secs;
    char str_name[32];
    int32_t i;

    gettimeofday(&now, NULL);
    for (i = 0; i < MAX_NB_SESS; i++){
        if (sh->sess[i]) {
	    secs = (now.tv_sec - sh->sess[i]->ts_start.tv_sec);
	    mins = secs / 60;
	    secs = secs % 60;
	    hours = mins / 60;
	    mins = mins % 60;
	    days = hours / 24;
	    hours = hours % 24;
	    strncpy(str_name, sh->sess[i]->name, sizeof(str_name));
	    str_name[sizeof(str_name) - 1] = '\0';

	    if (days)
		fprintf(cio, " %s: up %lu days %lu:%02lu:%02lu\n",
		        str_name, days, hours, mins, secs);
	    else
		fprintf(cio, " %s: up %lu:%02lu:%02lu\n",
		        str_name, hours, mins, secs);
	    }
    }
    return 0;
}

static int shcmd_uptime(FILE *cio, int argc, char *argv[])
{
    /* shows shell uptime */
    struct timeval now;
    uint64_t days = 0;
    uint64_t hours = 0;
    uint64_t mins = 0;
    uint64_t secs;

    gettimeofday(&now, NULL);
    secs = (now.tv_sec - sh->ts_start.tv_sec);
    mins = secs / 60;
    secs = secs % 60;
    hours = mins / 60;
    mins = mins % 60;
    days = hours / 24;
    hours = hours % 24;

    if (days)
        fprintf(cio, "up %lu days %lu:%02lu:%02lu\n", days, hours, mins, secs);
    else
        fprintf(cio, "up %lu:%02lu:%02lu\n", hours, mins, secs);
    return 0;
}

static int shcmd_date(FILE *cio, int argc, char *argv[])
{
    /* shows shell uptime */
    struct timeval now;
    struct tm *tm;
    time_t tsec;
    char str_date[64];

    gettimeofday(&now, NULL);
    tsec = (time_t) now.tv_sec;
    tm = localtime(&tsec);

    strftime(str_date, sizeof(str_date), "%c", tm);
    fprintf(cio, "%s\n", str_date);
    return 0;
}

static int shcmd_exit(FILE *cio, int argc, char *argv[])
{
    /* closes shell */
    return SH_CLOSE;
}

static int shcmd_clear(FILE *cio, int argc, char *argv[])
{
    /* echo args */
    fprintf(cio, "\e[H\e[J");
    fflush(cio);
    return 0;
}

static int shcmd_echo(FILE *cio, int argc, char *argv[])
{
    /* echo args */
    int i;

    for (i = 1; i < argc; i++) {
        if (i > 1)
            fprintf(cio, " ");
        fprintf(cio, "%s", argv[i]);
    }
    fprintf(cio, "\n");
    return 0;
}

static int shcmd_time(FILE *cio, int argc, char *argv[])
{
    /* run a shell command while measuring its execution time */
    int ret = 0;
    int32_t cmdi;
    struct timeval tm_start;
    struct timeval tm_end;
    uint64_t mins = 0;
    uint64_t secs = 0;
    uint64_t usecs = 0;

    if (argc == 1) {
        fprintf(cio, "Usage: %s [command] [[args]]...\n", argv[0]);
        return -1;
    }
    cmdi = shell_get_cmd_index(argv[1]);
    if (cmdi < 0) {
        fprintf(cio, "%s: command not found\n", argv[1]);
        goto out;
    }

    gettimeofday(&tm_start, NULL);
    ret = sh->cmd_func[cmdi](cio, argc - 1, &argv[1]);
    gettimeofday(&tm_end, NULL);

    if (tm_end.tv_usec < tm_start.tv_usec) {
	    tm_end.tv_usec += 1000000l;
	    --tm_end.tv_sec;
    }
    usecs = (tm_end.tv_usec - tm_start.tv_usec);
    secs = usecs / 1000000l + (tm_end.tv_sec - tm_start.tv_sec);
    usecs %= 1000000l;
    mins = secs / 60;
    secs %= 60;

 out:
    fprintf(cio, "%s: command runtime %lum%lu.%06lus\n", argv[1], mins, secs, usecs);
    return ret;
}


static int shcmd_repeat(FILE *cio, int argc, char *argv[])
{
    /* run a shell command multiple times */
    int ret = 0;
    int32_t cmdi;
    unsigned int arg_times, arg_delay;
    int do_delay = 0;

    if (argc <= 3)
	goto usage;
    if (sscanf(argv[1], "%u", &arg_times) != 1)
        goto usage;
    if (sscanf(argv[2], "%u", &arg_delay) != 1)
	goto usage;
    cmdi = shell_get_cmd_index(argv[3]);
    if (cmdi < 0) {
        fprintf(cio, "%s: command not found\n", argv[3]);
        return 0;
    }

    while (arg_times != 0 && ret >= 0 && ret != SH_CLOSE) {
	if (do_delay)
	    msleep(arg_delay);
	shcmd_clear(cio, 0, NULL);
	ret = sh->cmd_func[cmdi](cio, argc - 3, &argv[3]);
	fflush(cio);
	do_delay = 1;
	--arg_times;
    }
    return ret;

 usage:
    fprintf(cio, "Usage: %s [times] [delay-ms] [command] [[args]]...\n", argv[0]);
    return -1;
}


#ifdef SHELL_DEBUG
static int shcmd_args(FILE *cio, int argc, char *argv[])
{
    /* list args */
    int i;

    fprintf(cio, "argc: %d\n", argc);
    for (i = 0; i < argc; i++) {
        fprintf(cio, "argv(%d): %s\n", i, argv[i]);
    }
    return 0;
}
#endif
