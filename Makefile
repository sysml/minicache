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

CONFIG_START_NETWORK		= n
# use 'vale' for xenbus driver instead of 'vif'
CONFIG_NETMAP_XENBUS		= n
# POSIX netmap implementation
CONFIG_NETMAP			= n
CONFIG_NETMAP_API		= 4
CONFIG_MEMPOOL			= y
CONFIG_LWIP			= y
CONFIG_LWIP_MINIMAL		= y
CONFIG_LWIP_SINGLETHREADED 	= y

# enable NM_WRAP API/lwip-netif only
CONFIG_NETFRONT			= y
CONFIG_NETFRONT_NETMAP2		= n
CONFIG_NMWRAP			= n
CONFIG_NMWRAP_SYNCRX		= n

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

######################################
## HTTPd options
######################################
CFLAGS				+= -DHTTPD_SERVER_AGENT="\"MiniCache/$(_GITSHA1)\""

######################################
## General MiniCache options
######################################
CFLAGS				+= -DCONFIG_AUTOMOUNT

######################################
## Debugging options
######################################
CONFIG_DEBUG			= y
CONFIG_DEBUG_LWIP		= n
CFLAGS				+= -DCONFIG_MINDER_PRINT
//CFLAGS			+= -DHTTP_DEBUG
//CFLAGS			+= -DSHFS_DEBUG
//CFLAGS			+= -DSHELL_DEBUG

######################################
## MiniOS path
######################################
MINI_OS_ROOT	= $(realpath ./mini-os/)

######################################
## Stubdomain
######################################
STUBDOM_NAME	= minicache
STUBDOM_ROOT	= $(realpath .)

STUB_APP_OBJS0  = main.o shell.o http_parser.o http.o blkdev.o \
		  shfs.o shfs_check.o shfs_htable.o shfs_fio.o shfs_tools.o
STUB_APP_OBJS	= $(addprefix $(STUB_APP_OBJ_DIR)/,$(STUB_APP_OBJS0))

include $(MINI_OS_ROOT)/stub.mk
