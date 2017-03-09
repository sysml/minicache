MiniCache Scripts
=================
This directory contains a collection of various scripts
to be used with MiniCache.

Requirements
------------
Please ensure that you compiled MiniCache and
the following tools:
 * shfs-tools
 * ctltrigger

Scripts
-------
### Online SHFS modification
Enables you to change the content of an mounted SHFS
object store (by MiniCache on Xen). The scripts modify
the volume with ```shfs_admin``` and use ```ctltrigger```
to issue a remount.
 * ```add-obj.py```
 * ```rm-obj.py```

### Cache node statistic retrievel
Issues a command to MiniCache on Xen by using ```ctltrigger```
to write the current statistics to a defined block device.
The script reads the contents from the device and prints it
to stdout.
 * ```get-stats.py```

### SHFS filesystem creation
Automatically creates an SHFS filesystem image for a a given
directory. All files, including from subdirectories, are
included to the image.
 * ```mkwebfs```
