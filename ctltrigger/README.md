XenStore control dir trigger tool
=================================

This tool can be used to trigger XenStore

Requirements
------------

In order to build the XenStore control dir trigger tool tool, you will need to
have the following shared library installed:
 * [libxenstore](http://wiki.xen.org/wiki/XenStoreReference)

Usually it is installed when you have Xen isntalled but you
can install it manually on Debian/Ubuntu via:

    apt-get install libxenstore


Build Instructions
------------------

You build the tool with the following make command:

    make


Examples: Using ctltrigger with MiniCache
-----------------------------------------

### Unmount filesystem on MiniCache Dom-U 5

    ctltrigger 5 minicache umount

### Mount xvda (VBD ID is 51712) on MiniCache Dom-U 16

    ctltrigger 16 minicache mount 51712
