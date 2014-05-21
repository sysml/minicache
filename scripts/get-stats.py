#!/usr/bin/python
import os
import sys
import stat
import fcntl
import subprocess

CMD_CTLTRIGGER="../ctltrigger/ctltrigger"
BLKFLSBUF = 0x00001261 # from <linux/fs.h>
BYTESPERREAD = 512

def ctltrigger(domid, action, args=[], scope="minicache"):
    pargs = [CMD_CTLTRIGGER, domid, scope, action]
    pargs.extend(args)
    try:
        p = subprocess.Popen(pargs, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    except OSError as e:
        sys.stderr.write("Could not execute '%s': %s\n" % (CMD_CTLTRIGGER, e.strerror))
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
    sys.stderr.write("Could not request %s\n" % rc)

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
