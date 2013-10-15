default : all

######################################
## user defined
######################################
XEN_VER		?= 4.2.0
XEN_ROOT	?= $(realpath ../xen-$(XEN_VER))
TOOLCHAIN_ROOT	?= $(realpath ../toolchain.xen.$(XEN_VER))
GCC_VERSION	?= 4.5.0
verbose		?= 
debug		?= y

stubdom		= y

CFLAGS          += -Winline -Wtype-limits -Wcast-align --param large-stack-frame=256 --param large-stack-frame-growth=16

CONFIG_START_NETWORK	= n
CONFIG_NETFRONT		= n
# use 'vale' for xenbus driver instead of 'vif'
CONFIG_NETMAP_XENBUS	= y
# POSIX netmap implementation
CONFIG_NETMAP		= y
CONFIG_NETFRONT_NETMAP2	= n
lwip			= y

MINI_OS_ROOT	= $(realpath ./mini-os/)

STUBDOM_NAME	= minicache
STUBDOM_ROOT	= $(realpath .)

STUB_APP_OBJS0  = main.o hexdump.o ring.o mempool.o pktbuf.o nmdev.o blkdev.o
STUB_APP_OBJS	= $(addprefix $(STUB_APP_OBJ_DIR)/,$(STUB_APP_OBJS0))

include $(MINI_OS_ROOT)/stub.mk
