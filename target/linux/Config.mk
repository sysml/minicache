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
LN		 = ln -sf
MKDIR		 = mkdir -p
MV		 = mv -f
RM		 = rm -f
RMDIR		 = rm -rf
TOUCH		 = touch


#ifneq ($(verbose),y)
#ccompile			 = @/bin/echo ' ' $(2) $< && $(COMPILE) $(DEPCFLAGS) $(1)
#ccompile_nodep			 = @/bin/echo ' ' $(2) $< && $(COMPILE) $(1)
#ascompile			 = @/bin/echo ' ' $(2) $< && $(ASCOMPILE) $(DEPCFLAGS) $(1)
#ascompile_nodep			 = @/bin/echo ' ' $(2) $< && $(ASCOMPILE) $(1)
#cxxcompile			 = @/bin/echo ' ' $(2) $< && $(CXXCOMPILE) $(DEPCFLAGS) $(1)
#cxxcompile_nodep		 = @/bin/echo ' ' $(2) $< && $(CXXCOMPILE) $(1)
#cxxlink				 = @/bin/echo ' ' $(2) $< && $(CXXLINK) $(1)
#archive				 = @/bin/echo ' ' $(2) $@ && $(AR) cr $(1)
#x_verbose_cmd			 = $(if $(2),/bin/echo ' ' $(2) $(3) &&,) $(1) $(3)
#verbose_cmd			 = @$(x_verbose_cmd)
#MAKE				:= $(MAKE) --silent
#else
#ccompile			 = $(COMPILE) $(DEPCFLAGS) $(1)
#ccompile_nodep			 = $(COMPILE) $(1)
#ascompile			 = $(ASCOMPILE) $(DEPCFLAGS) $(1)
#ascompile_nodep			 = $(ASCOMPILE) $(1)
#cxxcompile			 = $(CXXCOMPILE) $(DEPCFLAGS) $(1)
#cxxcompile_nodep		 = $(CXXCOMPILE) $(1)
#cxxlink				 = $(CXXLINK) $(1)
#archive				 = $(AR) crv $(1)
#x_verbose_cmd			 = $(1) $(3)
#verbose_cmd			 = $(1) $(3)
#endif

CCDEP=gcc
CC=gcc

CFLAGS=-g -D$(TARGET) -DLWIP_DEBUG -pedantic -Werror \
	-Wparentheses -Wsequence-point -Wswitch-default \
	-Wextra -Wundef -Wshadow -Wpointer-arith -Wbad-function-cast \
	-Wc++-compat -Wwrite-strings -Wold-style-definition \
	-Wmissing-prototypes -Wredundant-decls -Wno-address #-Wnested-externs -Wall

# not used for now but interesting:
# -Wpacked
# -Wunreachable-code
# -ansi
# -std=c89
LDFLAGS=-pthread -lutil
ARFLAGS=rs

CONTRIBDIR		 = ../lwip-contrib
LWIPDIR			?= $(LWIP_ROOT)/src
MINICACHE_ROOT		?= $(realpath .)
LWIPARCH		 = $(MINICACHE_ROOT)/target/$(TARGET)
BUILDDIR		?= $(MINICACHE_ROOT)/build

CFLAGS:=$(CFLAGS) \
	-I. -I$(CONTRIBDIR)/apps/httpserver_raw -I$(CONTRIBDIR)/apps/shell \
	-I$(CONTRIBDIR)/apps/tcpecho -I$(CONTRIBDIR)/apps/udpecho \
	-I$(LWIPDIR)/include -I$(LWIPARCH) -I$(LWIPARCH)/include -I$(LWIPDIR)

# COREFILES, CORE4FILES: The minimum set of files needed for lwIP.
COREFILES=$(LWIPDIR)/core/def.c $(LWIPDIR)/core/dhcp.c $(LWIPDIR)/core/dns.c \
	$(LWIPDIR)/core/inet_chksum.c $(LWIPDIR)/core/init.c $(LWIPDIR)/core/mem.c \
	$(LWIPDIR)/core/memp.c $(LWIPDIR)/core/netif.c $(LWIPDIR)/core/pbuf.c \
	$(LWIPDIR)/core/raw.c $(LWIPDIR)/core/stats.c $(LWIPDIR)/core/sys.c \
	$(LWIPDIR)/core/tcp.c $(LWIPDIR)/core/tcp_in.c $(LWIPDIR)/core/tcp_in.c \
	$(LWIPDIR)/core/tcp_out.c $(LWIPDIR)/core/timers.c $(LWIPDIR)/core/udp.c
CORE4FILES=$(LWIPDIR)/core/ipv4/autoip.c $(LWIPDIR)/core/ipv4/icmp.c \
	$(LWIPDIR)/core/ipv4/igmp.c $(LWIPDIR)/core/ipv4/ip_frag.c \
	$(LWIPDIR)/core/ipv4/ip4.c $(LWIPDIR)/core/ipv4/ip4_addr.c
CORE6FILES=$(LWIPDIR)/core/ipv6/dhcp6.c $(LWIPDIR)/core/ipv6/ethip6.c \
	$(LWIPDIR)/core/ipv6/icmp6.c $(LWIPDIR)/core/ipv6/ip6.c \
	$(LWIPDIR)/core/ipv6/ip6_addr.c $(LWIPDIR)/core/ipv6/ip6_frag.c \
	$(LWIPDIR)/core/ipv6/mld6.c $(LWIPDIR)/core/ipv6/nd6.c

# SNMPFILES: Extra SNMPv1 agent
SNMPFILES=$(LWIPDIR)/core/snmp/asn1_dec.c $(LWIPDIR)/core/snmp/asn1_enc.c \
	$(LWIPDIR)/core/snmp/mib2.c $(LWIPDIR)/core/snmp/mib_structs.c \
	$(LWIPDIR)/core/snmp/msg_in.c $(LWIPDIR)/core/snmp/msg_out.c

# APIFILES: The files which implement the sequential and socket APIs.
APIFILES=$(LWIPDIR)/api/api_lib.c $(LWIPDIR)/api/api_msg.c $(LWIPDIR)/api/err.c \
	$(LWIPDIR)/api/netbuf.c $(LWIPDIR)/api/netdb.c $(LWIPDIR)/api/netifapi.c \
	$(LWIPDIR)/api/sockets.c $(LWIPDIR)/api/tcpip.c

# NETIFFILES: Files implementing various generic network interface functions.'
NETIFFILES=$(LWIPDIR)/netif/etharp.c $(LWIPDIR)/netif/slipif.c

# NETIFFILES: Add PPP netif
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

# ARCHFILES: Architecture specific files.
ARCHFILES=$(wildcard $(LWIPARCH)/*.c $(LWIPARCH)/netif/tapif.c $(LWIPARCH)/netif/tunif.c $(LWIPARCH)/netif/unixif.c $(LWIPARCH)/netif/list.c $(LWIPARCH)/netif/tcpdump.c)

# APPFILES: Applications.
APPFILES=$(CONTRIBDIR)/apps/httpserver_raw/fs.c $(CONTRIBDIR)/apps/httpserver_raw/httpd.c \
	$(CONTRIBDIR)/apps/udpecho/udpecho.c $(CONTRIBDIR)/apps/tcpecho/tcpecho.c \
	$(CONTRIBDIR)/apps/shell/shell.c

# LWIPFILES: All the above.
LWIPFILES=$(COREFILES) $(CORE4FILES) $(CORE6FILES) $(SNMPFILES) $(APIFILES) $(NETIFFILES) $(ARCHFILES)
LWIPFILESW=$(wildcard $(LWIPFILES))
LWIPOBJS=$(notdir $(LWIPFILESW:.c=.o))

LWIPLIB=liblwip.a
APPLIB=minicache.a
APPOBJS=$(notdir $(APPFILES:.c=.o))

%.o:
	$(CC) $(CFLAGS) -c $(<:.o=.c)

.PHONY: all
all: minicache

.PHONY: clean
clean:
	$(RM) *.o $(LWIPLIB) $(APPLIB) simhost *.s .depend* *.core core

.PHONY: distclean
distclean: clean

depend dep: .depend

include .depend

$(APPLIB): $(APPOBJS)
	$(AR) $(ARFLAGS) $(APPLIB) $?

$(LWIPLIB): $(LWIPOBJS)
	$(AR) $(ARFLAGS) $(LWIPLIB) $?

.depend: $(LWIPARCH)/simhost.c $(LWIPFILES) $(APPFILES)
	$(CCDEP) $(CFLAGS) -MM $^ > .depend || rm -f .depend

minicache: .depend $(LWIPLIB) $(APPLIB) simhost.o $(APPFILES)
	$(CC) $(CFLAGS) $(LDFLAGS) -o simhost simhost.o $(APPLIB) $(LWIPLIB)
