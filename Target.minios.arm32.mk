XEN_TARGET_ARCH		 = $(ARCH)
XEN_COMPILE_ARCH	 = $(ARCH)
XEN_ROOT		?= $(realpath ../xen)
TOOLCHAIN_ROOT		?= $(realpath ../toolchain)
MINIOS_ROOT		?= $(realpath ../mini-os)
NEWLIB_ROOT		?= $(TOOLCHAIN_ROOT)/$(ARCH)-root/arm-none-eabi
NEWLIB_PATH		?= $(NEWLIB_ROOT)
LWIP_ROOT		?= $(TOOLCHAIN_ROOT)/$(ARCH)-root/arm-none-eabi

GCC_VERSION		?= 4.7
CCTOOL			?= arm-linux-gnueabihf
CC			?= $(CCTOOL)-gcc-$(GCC_VERSION)
CXX			?= $(CCTOOL)-g++-$(GCC_VERSION)
AR			?= $(CCTOOL)-ar
AS			?= $(CCTOOL)-as
LD			?= $(CCTOOL)-ld
RANLIB			?= $(CCTOOL)-ranlib
READELF			?= $(CCTOOL)-readelf
STRIP			?= $(CCTOOL)-strip
NM			?= $(CCTOOL)-nm
OBJCOPY			?= $(CCTOOL)-objcopy

verbose			?=

######################################
## General
######################################
CONFIG_SHUTDOWN			 = y
CONFIG_CONSFRONT_SYNC		 = n

CFLAGS				+= -Wunused \
				   -Wtype-limits

######################################
## Networking
######################################
## vif
CONFIG_NETFRONT			 = y
CONFIG_NETFRONT_POLL		 = n
CONFIG_NETFRONT_POLLTIMEOUT	 = 1

## lwip
CONFIG_LWIP			 = y
CONFIG_LWIP_MINIMAL		 = y
CONFIG_LWIP_NOTHREADS		 = y
CONFIG_LWIP_HEAP_ONLY		 = y
CONFIG_LWIP_POOLS_ONLY		 = n
CONFIG_START_NETWORK		 = n

# support 1K TCP connections
CFLAGS				+= -DCONFIG_LWIP_NUM_TCPCON=1024

######################################
## Debugging
######################################
debug				?= n
CONFIG_DEBUG_LWIP		?= n
CONFIG_DEBUG_LWIP_MALLOC	?= n
#CFLAGS	       			+= -DLWIP_STATS_DISPLAY=1
#CFLAGS				+= -DLWIP_IF_DEBUG
#CFLAGS				+= -DLWIP_TCP_DEBUG

######################################
## Stub Domain
######################################
stubdom		 = y
STUBDOM_NAME	 = minicache
STUBDOM_ROOT	 = $(realpath .)

STUB_APP_OBJS0	 = main.o blkdev.o $(STUB_APP_OBJS0-y) $(MCOBJS)
STUB_APP_OBJS	 = $(addprefix $(STUB_APP_OBJ_DIR)/,$(STUB_APP_OBJS0))
CFLAGS		+= $(MCCFLAGS)

include $(MINIOS_ROOT)/stub.mk
