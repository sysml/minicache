default : all

######################################
## General configuration
######################################
XEN_VER		?= 4.2.0
XEN_ROOT	?= $(realpath ../xen-$(XEN_VER))
TOOLCHAIN_ROOT	?= $(realpath ../toolchain.xen.$(XEN_VER))
GCC_VERSION	?= 4.5.0
verbose		?=
stubdom		 = y

CFLAGS          += -Wunused -Winline -Wtype-limits -Wcast-align --param large-stack-frame=256 --param large-stack-frame-growth=16


######################################
## Networking options
######################################

## vif
CONFIG_NETMAP			= n

ifeq ($(CONFIG_NETMAP),y)
# use 'vale' for xenbus driver instead of 'vif'
CONFIG_NETMAP_XENBUS		= y
# POSIX netmap implementation
CONFIG_NETMAP_API		= 4
CONFIG_NETFRONT			= n
CONFIG_NETFRONT_NETMAP2		= n
CONFIG_NMWRAP			= y
CONFIG_NMWRAP_SYNCRX		= n
CFLAGS				+= -DNETMAP_DEBUG=0
else
CONFIG_NETMAP_XENBUS		= n
CONFIG_NETFRONT			= y
CONFIG_NETFRONT_NETMAP2		= n
CONFIG_NMWRAP			= n
endif
CONFIG_START_NETWORK		= n

## lwip
CONFIG_LWIP			= y
CONFIG_LWIP_MINIMAL		= y
CONFIG_LWIP_SINGLETHREADED 	= y
CONFIG_LWIP_HEAP_ONLY		= n
CONFIG_LWIP_POOLS_ONLY		= n

# support 4K TCP connections
#CFLAGS				+= -DCONFIG_LWIP_NUM_TCPCON=4096

# support 1K TCP connections
CFLAGS				+= -DCONFIG_LWIP_NUM_TCPCON=1024

######################################
## Shell options
######################################
_GITSHA1			= $(shell git rev-parse --short HEAD || echo "?")
CFLAGS				+= -DSHELL_INFO="\"MiniCache $(_GITSHA1)\nCopyright(C) 2013-2014 NEC Laboratories Europe Ltd.\"" \
				   -DSHELL_WELCOME="\"MiniCache $(_GITSHA1)\nCopyright(C) 2013-2014 NEC Laboratories Europe Ltd.\n\nType 'help' to get an overview of available commands\""
//CFLAGS			+= -DSHELL_PROMPT="\"mc\#\""
# colored prompt #
CFLAGS				+= -DSHELL_PROMPT="\"\\e[01;31mmc\\e[00m\#\""

######################################
## SHFS options
######################################
CFLAGS				+= -DSHFS_OPENBYNAME
CFLAGS				+= -DSHFS_STATS
//CFLAGS				+= -DSHFS_CACHE_STATS_DISPLAY

# Advanced statistics from HTTP
#  This enables counting the number of successful downloads
#  (including range requests) and download progress
#  counters (see: DPCR)
CFLAGS				+= -DSHFS_STATS_HTTP

CFLAGS				+= -DSHFS_STATS_HTTP_DPC
# Download progress counters resolution (DPCR)
#  e.g., DPDR=6 means 6 counter values:
#  VAL1: HTTP request counts that downloaded >=   0% of file
#  VAL2: HTTP request counts that downloaded >=  20% of file
#  VAL3: HTTP request counts that downloaded >=  40% of file
#  VAL4: HTTP request counts that downloaded >=  60% of file
#  VAL5: HTTP request counts that downloaded >=  80% of file
#  VAL6: HTTP request counts that downloaded  = 100% of file
#
#  Note: DPCR has to be at least 2 for a 0% and 100% counter
#        otherwise this feature is disabled
CFLAGS				+= -DSHFS_STATS_HTTP_DPCR=6

######################################
## HTTP options
######################################
CFLAGS				+= -DHTTP_SERVER_AGENT="\"MiniCache/$(_GITSHA1)\""
//CFLAGS			+= -DHTTP_TESTFILE
CFLAGS				+= -DHTTP_STATS_DISPLAY

######################################
## ctldir options
######################################
CFLAGS				+= -DCTLDIR_NOCHMOD

######################################
## General MiniCache options
######################################
CFLAGS				+= -DCONFIG_AUTOMOUNT

######################################
## Debugging options
######################################
CONFIG_DEBUG			= y
CONFIG_DEBUG_LWIP		= n
CONFIG_DEBUG_LWIP_MALLOC	= n
//CFLAGS	       		+= -DLWIP_STATS_DISPLAY=1
//CFLAGS			+= -DLWIP_IF_DEBUG
//CFLAGS			+= -DLWIP_TCP_DEBUG
//CFLAGS			+= -DCONFIG_MINDER_PRINT
//CFLAGS			+= -DHTTP_DEBUG
//CFLAGS			+= -DSHFS_DEBUG
//CFLAGS			+= -DSHFS_CACHE_DEBUG
//CFLAGS			+= -DSHELL_DEBUG
//CFLAGS			+= -DHTABLE_DEBUG
//CFLAGS			+= -DMEMPOOL_DEBUG
CFLAGS				+= -DTRACE_BOOTTIME

######################################
## MiniOS path
######################################
MINI_OS_ROOT	= $(realpath ./mini-os/)

######################################
## Stubdomain
######################################
STUBDOM_NAME	= minicache
STUBDOM_ROOT	= $(realpath .)

STUB_APP_OBJS0  = main.o mempool.o debug.o htable.o shell.o http_parser.o http.o blkdev.o \
		  ctldir.o shfs.o shfs_check.o shfs_cache.o shfs_fio.o shfs_tools.o shfs_stats.o
STUB_APP_OBJS	= $(addprefix $(STUB_APP_OBJ_DIR)/,$(STUB_APP_OBJS0))

include $(MINI_OS_ROOT)/stub.mk
