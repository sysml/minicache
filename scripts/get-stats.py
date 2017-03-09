#!/usr/bin/python

#
# MiniCache Tools
#
# Authors: Simon Kuenzer <simon.kuenzer@neclab.eu>
#
#
# Copyright (c) 2013-2017, NEC Europe Ltd., NEC Corporation All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. Neither the name of the copyright holder nor the names of its
#    contributors may be used to endorse or promote products derived from
#    this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# THIS HEADER MAY NOT BE EXTRACTED OR MODIFIED IN ANY WAY.
#

import os
import sys
import stat
import fcntl
import subprocess

CMDA_CTLTRIGGER="ctltrigger" # expected to be in $PATH
CMDB_CTLTRIGGER="../ctltrigger/ctltrigger" # alternatively
BLKFLSBUF = 0x00001261 # from <linux/fs.h>
BYTESPERREAD = 512

def ctltrigger(domid, action, args=[], scope="minicache"):
    pargs = [CMDA_CTLTRIGGER, domid, scope, action]
    pargs.extend(args)
    try:
        p = subprocess.Popen(pargs, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    except OSError as e:
        if e.errno == os.errno.ENOENT:
            try:
                # try again with CMDB
                pargs = [CMDB_CTLTRIGGER, domid, scope, "--", action]
                pargs.extend(args)
                p = subprocess.Popen(pargs, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
            except OSError as e:
                sys.stderr.write("Could not execute '%s': %s\n" % (CMDB_CTLTRIGGER, e.strerror))
                exit(1)
        else:
            sys.stderr.write("Could not execute '%s': %s\n" % (CMDA_CTLTRIGGER, e.strerror))
            exit(1)
    (pout, perr) = p.communicate("")
    prc = p.returncode
    if prc != 0:
        return(1)
    return(int(pout))

def usage():
    sys.stderr.write("Usage: %s [DOMID] [STATSDEV]\n" % sys.argv[0])
    exit(1)

##---------------------------------------------------------------
## MAIN
##---------------------------------------------------------------

# check arguments
if len(sys.argv) < 3:
    usage()

# try to open device
try:
    sdev = os.open(sys.argv[2], os.O_RDONLY)
except (OSError, IOError) as e:
    sys.stderr.write("Could not open '%s': %s\n" % (sys.argv[2], e.strerror))
    usage()

# ensure that sdev is a file or block device
sdev_info = os.fstat(sdev)
sdev_isblk = stat.S_ISBLK(sdev_info.st_mode)
if not sdev_isblk and not stat.S_ISREG(sdev_info.st_mode):
    sys.stderr.write("Could not open '%s': %s\n" % (sys.argv[2], "Is not a regular file or block device"))
    usage()

# trigger stats export
rc = ctltrigger(domid=sys.argv[1], action="export-stats")
if rc != 0:
    sys.stderr.write("Could not trigger action 'export-stats' on Domain %s\n" % sys.argv[1])
    exit(1)

# discard OS's buffer caches for block devices
if sdev_isblk:
    try:
        #fcntl.ioctl(sdev, BLKFLSBUF, 0)
        open('/proc/sys/vm/drop_caches','w').write("1\n")
    except (OSError, IOError) as e:
        sys.stderr.write("Could not reset cache for '%s': %s\n" % (sys.argv[2], e.strerror))
        exit(1)

# read sdev content and print it to stdout
# (read until '\0')
try:
    while True:
        blen = BYTESPERREAD
        buf  = os.read(sdev, BYTESPERREAD)
        blen = len(buf)
        for i, c in enumerate(buf):
            if c[0] == '\0':
                blen = i
                break
        sys.stdout.write(buf[:blen])
        if blen < BYTESPERREAD:
            break
except (OSError, IOError) as e:
    sys.stderr.write("Read error on '%s': %s\n" % (sys.argv[2], e.strerror))
    sys.stderr.write("Statistics are most likely incomplete\n")

# exit
os.close(sdev)
exit(0)
