#!/usr/bin/python
import os
import sys
import getopt
import subprocess

CMDA_SHFSADMIN="shfs_admin" # expected to be in $PATH
CMDB_SHFSADMIN="../shfs-tools/shfs_admin" # alternatively
CMDA_CTLTRIGGER="ctltrigger" # expected to be in $PATH
CMDB_CTLTRIGGER="../ctltrigger/ctltrigger" # alternatively

def shfsadmin(args=[]):
    pargs = [CMDA_SHFSADMIN, '-v', '-f']
    pargs.extend(args)
    try:
        p = subprocess.Popen(pargs, stdin=subprocess.PIPE)
    except OSError as e:
        if e.errno == os.errno.ENOENT:
            try:
                # try again with CMDB
                pargs = [CMDB_SHFSADMIN, '-v', '-f']
                pargs.extend(args)
                p = subprocess.Popen(pargs, stdin=subprocess.PIPE)
            except OSError as e:
                sys.stderr.write("Could not execute '%s': %s\n" % (CMDB_SHFSADMIN, e.strerror))
                exit(1)
        else:
            sys.stderr.write("Could not execute '%s': %s\n" % (CMDA_SHFSADMIN, e.strerror))
            exit(1)
    perr = p.communicate("")
    prc = p.returncode
    return(prc)

def ctltrigger(domid, action, args=[], scope="minicache"):
    pargs = [CMDA_CTLTRIGGER, domid, scope, action]
    pargs.extend(args)
    try:
        p = subprocess.Popen(pargs, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    except OSError as e:
        if e.errno == os.errno.ENOENT:
            try:
                # try again with CMDB
                pargs = [CMDB_CTLTRIGGER, domid, scope, action]
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
    sys.stderr.write("Usage: %s [OPTION]... [DEVICE]...\n" % sys.argv[0])
    sys.stderr.write("  -r, --rm-file [HASH]       removes a file from the volume\n");
    exit(1)

##---------------------------------------------------------------
## MAIN
##---------------------------------------------------------------

# check arguments
try:
    opts, rem_args = getopt.getopt(sys.argv[1:], "d:r:h", ["dom=", "rm-file=", "help"])
except getopt.GetoptError as err:
    sys.stderr.write(str(err))
    usage()

dom = []
rm = []
for o, a in opts:
    if o in ("-d", "--dom"):
        try:
            if int(a) <= 0:
                sys.stderr.write("'%s' is an invalid domain ID\n" % a)
                exit(1)
            dom.append(str(int(a)))
        except ValueError as e:
            sys.stderr.write("'%s' is an invalid domain ID\n" % a)
            exit(1)
    elif o in ("-r", "--rm-file"):
        rm.append(a)
    elif o in ("-h", "--help"):
        usage()
        exit(0)
    else:
        sys.stderr.write("Unrecognized option: %s\n", o)
        usage()
        exit(1)

if len(sys.argv) < 3:
    usage()

# run shfs_admin
args = []
for r in rm:
    args.extend(['-r', r])
args.extend(rem_args)
shfsadmin(args=args)

# trigger remount
# TODO: parallelize triggering remount/update
for d in dom:
    sys.stdout.write("Trigger action 'remount' on Domain %s\n" % d)
    rc = ctltrigger(domid=d, action="remount")
    if rc != 0:
        sys.stderr.write("Could not trigger action 'remount' on Domain %s\n" % d)

# exit
exit(0)
