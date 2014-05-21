MiniCache: XenStore control dir trigger reference
=================================================

XenStore control triggers are XenStore interfaces to specific commands.
Their execution can be triggered by using the `ctltrigger` command.
Please refer its help to get an overview of its usage.

```
export-stats
```
 Exports collected access statistics to the configured stats device.

```
mount [VBD ID]...
```
 Mounts an SHFS volume. Multiple devices can be passed to the command.
 In this case, mount will search for SHFS volumes an all devices
 and will mount the first valid one. This is also required when multi-member
 volumes shall be mounted.

```
remount
```
 Re-mounts the currently mounted SHFS volume.

```
umount
```
 Un-mounts the currently mounted SHFS volume.
