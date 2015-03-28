#
# MiniCache Linux Target: Makefile
#
#   file: Target.linux.x86_64.mk
#
###########################################################################
#
#          NEC Europe Ltd. PROPRIETARY INFORMATION
#
# This software is supplied under the terms of a license agreement
# or nondisclosure agreement with NEC Europe Ltd. and may not be
# copied or disclosed except in accordance with the terms of that
# agreement. The software and its source code contain valuable trade
# secrets and confidential information which have to be maintained in
# confidence.
# Any unauthorized publication, transfer to third parties or duplication
# of the object or source code - either totally or in part – is
# prohibited.
#
#      Copyright (c) 2015 NEC Europe Ltd. All Rights Reserved.
#
# Authors: Simon Kuenzer <simon.kuenzer@neclab.eu>
#
# NEC Europe Ltd. DISCLAIMS ALL WARRANTIES, EITHER EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS FOR A PARTICULAR PURPOSE AND THE WARRANTY AGAINST LATENT
# DEFECTS, WITH RESPECT TO THE PROGRAM AND THE ACCOMPANYING
# DOCUMENTATION.
#
# No Liability For Consequential Damages IN NO EVENT SHALL NEC Europe
# Ltd., NEC Corporation OR ANY OF ITS SUBSIDIARIES BE LIABLE FOR ANY
# DAMAGES WHATSOEVER (INCLUDING, WITHOUT LIMITATION, DAMAGES FOR LOSS
# OF BUSINESS PROFITS, BUSINESS INTERRUPTION, LOSS OF INFORMATION, OR
# OTHER PECUNIARY LOSS AND INDIRECT, CONSEQUENTIAL, INCIDENTAL,
# ECONOMIC OR PUNITIVE DAMAGES) ARISING OUT OF THE USE OF OR INABILITY
# TO USE THIS PROGRAM, EVEN IF NEC Europe Ltd. HAS BEEN ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGES.
#
#     THIS HEADER MAY NOT BE EXTRACTED OR MODIFIED IN ANY WAY.
#
###########################################################################
#
# Copyright (c) 2001, 2002 Swedish Institute of Computer Science.
# All rights reserved. 
# 
# Redistribution and use in source and binary forms, with or without modification, 
# are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
# 3. The name of the author may not be used to endorse or promote products
#    derived from this software without specific prior written permission. 
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED 
# WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF 
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT 
# SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, 
# EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT 
# OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING 
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY 
# OF SUCH DAMAGE.
#
# This file is part of the lwIP TCP/IP stack.
# 
# Author: Adam Dunkels <adam@sics.se>
#
###########################################################################

ifndef LWIP_ROOT
$(error "Please define LWIP_ROOT")
endif

###########################################################################

CONFIG_CTLDIR = n # ctldir is not supported on linuxapp
CONFIG_SHELL = n # shell is not supported on linuxapp, yet
CONFIG_SHFS_STATS = n # no stats
CONFIG_TESTSUITE = n # no testuite

CONFIG_MINICACHE_MINDER_PRINT = y


include Minicache.mk

#################################

LN		 = ln -sf
MKDIR		 = mkdir -p
MV		 = mv -f
RM		 = rm -f
RMDIR		 = rm -rf
TOUCH		 = touch

CCDEP=gcc
CC=gcc

CFLAGS+=-g -D$(TARGET) $(MCCFLAGS) \
	-Wparentheses -Wsequence-point -Wswitch-default \
	-Wundef -Wpointer-arith -Wbad-function-cast \
	-Wwrite-strings -Wold-style-definition \
	-Wmissing-prototypes -Wredundant-decls -Wno-address # -Wextra -Wnested-externs -Wall -Wshadow
# -pedantic \

# not used for now but interesting:
# -Wpacked
# -Wunreachable-code
# -ansi
# -std=c89
LDFLAGS+=-pthread -lrt #-lutil
ARFLAGS=rs

ifeq ($(BUILDSO),y)
CFLAGS+=-fPIC -DLWIP_DNS_API_DECLARE_H_ERRNO=0
endif

CONTRIBDIR		 = ../lwip-contrib
LWIPDIR		?= $(LWIP_ROOT)/src
MINICACHE_ROOT		?= $(realpath .)
LWIPARCH		 = $(MINICACHE_ROOT)/target/$(TARGET)
BUILDDIR		?= $(MINICACHE_ROOT)/build
ifneq ($(BUILDSO),y)
MINICACHE_OUT		?= minicache_$(ARCH)
else
MINICACHE_OUT		?= minicache_$(ARCH).so
endif

CFLAGS:=$(CFLAGS) \
	-I. -Itarget/$(TARGET)/include \
	-I$(LWIPDIR)/include -I$(LWIPARCH) -I$(LWIPARCH)/include -I$(LWIPDIR)

# COREFILES, CORE4FILES: The minimum set of files needed for lwIP.
COREDIRS=$(LWIPDIR)/core
COREFILES=$(LWIPDIR)/core/def.c $(LWIPDIR)/core/dhcp.c $(LWIPDIR)/core/dns.c \
	$(LWIPDIR)/core/inet_chksum.c $(LWIPDIR)/core/init.c $(LWIPDIR)/core/mem.c \
	$(LWIPDIR)/core/memp.c $(LWIPDIR)/core/netif.c $(LWIPDIR)/core/pbuf.c \
	$(LWIPDIR)/core/raw.c $(LWIPDIR)/core/stats.c $(LWIPDIR)/core/sys.c \
	$(LWIPDIR)/core/tcp.c $(LWIPDIR)/core/tcp_in.c $(LWIPDIR)/core/tcp_in.c \
	$(LWIPDIR)/core/tcp_out.c $(LWIPDIR)/core/timers.c $(LWIPDIR)/core/udp.c
CORE4DIRS=$(LWIPDIR)/core/ipv4
CORE4FILES=$(LWIPDIR)/core/ipv4/autoip.c $(LWIPDIR)/core/ipv4/icmp.c \
	$(LWIPDIR)/core/ipv4/igmp.c $(LWIPDIR)/core/ipv4/ip_frag.c \
	$(LWIPDIR)/core/ipv4/ip4.c $(LWIPDIR)/core/ipv4/ip4_addr.c
CORE6DIRS=$(LWIPDIR)/core/ipv6
CORE6FILES=$(LWIPDIR)/core/ipv6/dhcp6.c $(LWIPDIR)/core/ipv6/ethip6.c \
	$(LWIPDIR)/core/ipv6/icmp6.c $(LWIPDIR)/core/ipv6/ip6.c \
	$(LWIPDIR)/core/ipv6/ip6_addr.c $(LWIPDIR)/core/ipv6/ip6_frag.c \
	$(LWIPDIR)/core/ipv6/mld6.c $(LWIPDIR)/core/ipv6/nd6.c

# APIFILES: The files which implement the sequential and socket APIs.
APIDIRS=$(LWIPDIR)/api
APIFILES=$(LWIPDIR)/api/api_lib.c $(LWIPDIR)/api/api_msg.c $(LWIPDIR)/api/err.c \
	$(LWIPDIR)/api/netbuf.c $(LWIPDIR)/api/netdb.c $(LWIPDIR)/api/netifapi.c \
	$(LWIPDIR)/api/sockets.c $(LWIPDIR)/api/tcpip.c

# NETIFFILES: Files implementing various generic network interface functions.'
NETIFDIRS=$(LWIPDIR)/netif
NETIFFILES=$(LWIPDIR)/netif/etharp.c $(LWIPDIR)/netif/slipif.c

# NETIFFILES: Add PPP netif
NETIFDIRS+=:$(LWIPDIR)/netif/ppp:$(LWIPDIR)/netif/ppp/polarssl:$(LWIPARCH)/netif
NETIFFILES+=$(LWIPDIR)/netif/ppp/auth.c $(LWIPDIR)/netif/ppp/ccp.c \
	$(LWIPDIR)/netif/ppp/chap-md5.c $(LWIPDIR)/netif/ppp/chap_ms.c \
	$(LWIPDIR)/netif/ppp/chap-new.c $(LWIPDIR)/netif/ppp/demand.c \
	$(LWIPDIR)/netif/ppp/eap.c $(LWIPDIR)/netif/ppp/ecp.c \
	$(LWIPDIR)/netif/ppp/eui64.c $(LWIPDIR)/netif/ppp/fsm.c \
	$(LWIPDIR)/netif/ppp/ipcp.c $(LWIPDIR)/netif/ppp/ipv6cp.c \
	$(LWIPDIR)/netif/ppp/lcp.c $(LWIPDIR)/netif/ppp/magic.c \
	$(LWIPDIR)/netif/ppp/multilink.c $(LWIPDIR)/netif/ppp/ppp.c \
	$(LWIPDIR)/netif/ppp/pppcrypt.c $(LWIPDIR)/netif/ppp/pppoe.c \
	$(LWIPDIR)/netif/ppp/pppol2tp.c $(LWIPDIR)/netif/ppp/upap.c \
	$(LWIPDIR)/netif/ppp/utils.c $(LWIPDIR)/netif/ppp/vj.c \
	$(LWIPDIR)/netif/ppp/polarssl/des.c $(LWIPDIR)/netif/ppp/polarssl/md4.c \
	$(LWIPDIR)/netif/ppp/polarssl/md5.c $(LWIPDIR)/netif/ppp/polarssl/sha1.c \
	$(LWIPARCH)/netif/sio.c
# SNMPFILES: Extra SNMPv1 agent
SNMPFILES=$(LWIPDIR)/core/snmp/asn1_dec.c $(LWIPDIR)/core/snmp/asn1_enc.c \
	$(LWIPDIR)/core/snmp/mib2.c $(LWIPDIR)/core/snmp/mib_structs.c \
	$(LWIPDIR)/core/snmp/msg_in.c $(LWIPDIR)/core/snmp/msg_out.c \
	$(LWIPARCH)/lwip_prvmib.c
SNMPDIRS=$(LWIPDIR)/core/snmp

# ARCHFILES: Architecture specific files.
ARCHFILES=$(wildcard $(LWIPARCH)/*.c $(LWIPARCH)/netif/tapif.c $(LWIPARCH)/netif/tunif.c $(LWIPARCH)/netif/unixif.c $(LWIPARCH)/netif/list.c $(LWIPARCH)/netif/tcpdump.c)

# APPFILES: Applications.
APPDIRS=.:target/$(TARGET)
APPFILES=$(MCOBJS)
APPFILESW=$(addprefix $(BUILDDIR)/,$(notdir $(APPFILES)))
APPOBJS=$(addprefix $(BUILDDIR)/,$(notdir $(APPFILESW:.c=.o)))

# LWIPFILES: All the above.
LWIPFILES=$(COREFILES) $(CORE4FILES) $(CORE6FILES) $(SNMPFILES) $(APIFILES) $(NETIFFILES) $(ARCHFILES)
LWIPFILESW=$(wildcard $(LWIPFILES))
LWIPOBJS=$(addprefix $(BUILDDIR)/,$(notdir $(LWIPFILES:.c=.o)))

ifneq ($(BUILDSO),y)
LWIPLIB=$(BUILDDIR)/liblwip.a
APPLIB=$(BUILDDIR)/minicache.a
else
LWIPLIB=$(BUILDDIR)/liblwip.so
endif

# set source search path
VPATH=$(BUILDDIR):$(LWIPARCH):$(COREDIRS):$(CORE4DIRS):$(CORE6DIRS):$(SNMPDIRS):$(APIDIRS):$(NETIFDIRS):$(APPDIRS)

include $(BUILDDIR)/.depend

.PHONY: clean
clean:
	$(RM) $(BUILDDIR)/*.o $(BUILDDIR)/$(LWIPLIB) $(BUILDDIR)/$(APPLIB) $(BUILDDIR)/$(MINICACHE_OUT) $(BUILDDIR)/*.s $(BUILDDIR)/.depend* $(BUILDDIR)/*.core $(BUILDDIR)/core

.PHONY: distclean
distclean:
	$(RMDIR) $(BUILDDIR)

.PHONY: all
all: $(BUILDDIR)/$(MINICACHE_OUT)

.PHONY: build
build: $(BUILDDIR) $(BUILDDIR)/.depend $(BUILDDIR)/$(MINICACHE_OUT)

$(BUILDDIR):
	$(MKDIR) $@

$(BUILDDIR)/%.o: %.c | $(BUILDDIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILDDIR)/%.a: %.o
	$(AR) $(ARFLAGS) -o $@ $^

$(BUILDDIR)/.depend: $(BUILDDIR) $(LWIPFILES) $(APPFILES) | $(BUILDDIR)
	$(CCDEP) $(CFLAGS) -MM $^ > $(BUILDDIR)/.depend || $(RM) $(BUILDDIR)/.depend

.PHONY: $(BUILDDIR)/$(MINICACHE_OUT)
ifneq ($(BUILDSO),y)
$(LWIPLIB): $(LWIPOBJS)
	$(AR) $(ARFLAGS) $(LWIPLIB) $?

$(APPLIB): $(APPOBJS)
	$(AR) $(ARFLAGS) $(APPLIB) $?

$(BUILDDIR)/$(MINICACHE_OUT): $(BUILDDIR)/.depend $(LWIPLIB) $(APPLIB) $(APPFILES)
	$(CC) $(APPLIB) $(LWIPLIB) $(LDFLAGS) -o $(BUILDDIR)/$(MINICACHE_OUT)
else
$(LWIPLIB): $(LWIPOBJS)
	$(CC) $(LDFLAGS) $? -shared -o $(LWIPLIB)

$(BUILDDIR)/$(MINICACHE_OUT): $(BUILDDIR)/.depend $(LWIPLIB) $(APPOBJS) $(APPFILES)
	$(CC) $(APPOBJS) -l:$(LWIPLIB) $(LDFLAGS) -shared -o $(BUILDDIR)/$(MINICACHE_OUT)
endif
