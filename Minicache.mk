###################
# General
###################
MCCFLAGS					+= -I.
MCCFLAGS					+= -DCONFIG_BANNER_VERSION="\"MiniCache/$(GITSHA1)/$(ARCH)\""
MCCFLAGS-$(CONFIG_MINICACHE_HIDE_BANNER)	+= -DCONFIG_HIDE_BANNER
MCCFLAGS-$(CONFIG_MINICACHE_AUTOMOUNT)		+= -DCONFIG_AUTOMOUNT
MCCFLAGS-$(CONFIG_MINICACHE_MINDER_PRINT)	+= -DCONFIG_MINDER_PRINT
MCCFLAGS-$(CONFIG_MINICACHE_TRACE_BOOTTIME)	+= -DTRACE_BOOTTIME

MCOBJS						= ring.o \
						  mempool.o \
						  hexdump.o \
						  debug.o \
						  htable.o \
						  shfs.o \
						  shfs_check.o \
						  shfs_cache.o \
						  shfs_fio.o \
						  shfs_tools.o \
						  http_parser.o \
						  http_fio.o \
						  http_link.o \
						  http.o \
						  minicache.o \
						  target/$(TARGET)/blkdev.o

MCCFLAGS-$(CONFIG_HTABLE_DEBUG)			+= -DHTABLE_DEBUG
MCCFLAGS-$(CONFIG_MEMPOOL_DEBUG)		+= -DMEMPOOL_DEBUG


######################################
## µSh
######################################
ifeq ($(CONFIG_SHELL),y)
MCCFLAGS	+= -DSHELL_INFO="\"MiniCache/$(GITSHA1)/$(ARCH) (built: $(shell date +%F))\nCopyright(C) 2013-2015 NEC Laboratories Europe Ltd.\"" \
		   -DSHELL_WELCOME="\"MiniCache $(GITSHA1)\nCopyright(C) 2013-2015 NEC Laboratories Europe Ltd.\n\nType 'help' to get an overview of available commands\""

ifeq ($(CONFIG_SHELL_COLORPROMPT),y)
MCCFLAGS	+= -DSHELL_PROMPT="\"\\e[01;31mmc\\e[00m\#\""
else
MCCFLAGS	+= -DSHELL_PROMPT="\"mc\#\""
endif

MCOBJS		+= shell.o
MCCFLAGS	+= -DHAVE_SHELL
endif
MCCFLAGS-$(CONFIG_SHELL_DEBUG)		+= -DSHELL_DEBUG

######################################
## ctldir (only available on Mini-OS)
######################################
ifeq ($(TARGET),minios)
MCCFLAGS-$(CONFIG_CTLDIR)		+= -DHAVE_CTLDIR
MCCFLAGS-$(CONFIG_CTLDIR_NOCHMOD)	+= -DCTLDIR_NOCHMOD
MCOBJS-$(CONFIG_CTLDIR)		+= target/$(TARGET)/ctldir.o
endif

######################################
## SHFS
######################################
MCCFLAGS-$(CONFIG_SHFS_OPENBYNAME)	+= -DSHFS_OPENBYNAME
MCCFLAGS-$(CONFIG_SHFS_CACHEINFO)	+= -DSHFS_CACHE_INFO
MCCFLAGS-$(CONFIG_SHFS_DEBUG)		+= -DSHFS_DEBUG
MCCFLAGS-$(CONFIG_SHFS_CACHE_DEBUG)	+= -DSHFS_CACHE_DEBUG
ifeq ($(CONFIG_SHFS_STATS),y)
MCCFLAGS				+= -DSHFS_STATS
MCOBJS					+= shfs_stats.o
ifeq ($(CONFIG_SHFS_STATS_HTTP),y)
MCCFLAGS				+= -DSHFS_STATS_HTTP
#ifeq ($(shell echo ${CONFIG_SHFS_STATS_HTTP_DPCR}\>=2 | bc),"1")
MCCFLAGS				+= -DSHFS_STATS_HTTP_DPC \
					   -DSHFS_STATS_HTTP_DPCR=$(CONFIG_SHFS_STATS_HTTP_DPCR)
#endif
endif
endif

CONFIG_SHFS_CACHE_READAHEAD		?= 8
MCCFLAGS				+= -DSHFS_CACHE_READAHEAD=$(CONFIG_SHFS_CACHE_READAHEAD)

######################################
## HTTP
######################################
MCCFLAGS				+= -DHTTP_SERVER_AGENT="\"MiniCache/$(GITSHA1)\""
MCCFLAGS-$(CONFIG_HTTP_TESTFILE)	+= -DHTTP_TESTFILE
ifneq ($(CONFIG_HTTP_TESTFILE_SIZE),)
MCCFLAGS-$(CONFIG_HTTP_TESTFILE)	+= -DHTTP_TESTFILE_LEN=$(CONFIG_HTTP_TESTFILE_SIZE)
endif
MCCFLAGS-$(CONFIG_HTTP_INFO)		+= -DHTTP_INFO
MCCFLAGS-$(CONFIG_HTTP_URL_CUTARGS)	+= -DHTTP_URL_CUTARGS

MCCFLAGS-$(CONFIG_HTTP_DEBUG)		+= -DHTTP_DEBUG
MCCFLAGS-$(CONFIG_HTTP_DEBUG_PRINTACCESS) += -DHTTP_DEBUG_PRINTACCESS

######################################
## Misc
######################################
MCCFLAGS-$(CONFIG_TESTSUITE)		+= -DTESTSUITE
MCOBJS-$(CONFIG_TESTSUITE)		+= testsuite.o

######################################
MCOBJS					+= $(MCOBJS-y)
MCCFLAGS				+= $(MCCFLAGS-y)
