#
# MiniCache OSv Target: Makefile
#
#   file: Target.osv.x86_64.mk
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

TARGET=linux
CONFIG_OSVAPP=y
CONFIG_PTH_THREADS=n
CONFIG_SHELL=n

CFLAGS+=-DCONFIG_LWIP_CHECKSUM_NOCHECK

include Target.$(TARGET).$(ARCH).mk
