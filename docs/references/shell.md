MiniCache: µShell command reference
===================================

µShell is a telnet server built-into MiniCache.
By using `telnet [IP/DNS of CACHE]`, a shell session is established.

```
cat [FILE]...
```
 Displays FILE contents.

```
clear
```
 Clears screen.

```
date
```
 Displays current system time and date (Note: Times are displayed in UTC/GMT).

```
df [FILE]
```
 Displays hexdump of FILE contents.

```
echo [[STRING]]...
```
 Prints arguments.

```
exit
```
 Closes session.

```
export-stats
```
 Exports collected access statistics to the configured stats device.

```
file [FILE]...
```
 Displays MIME-type and size of FILE.

```
flush
```
 Flushes the disk block cache.

```
free [[-k|-m|-g|-p|-u]]
```
 Displays current memory usage.

```
halt
```
 Shutdowns system.

```
help
```
 Displays command overview.

```
ifconfig
```
 Lists configured network interfaces and their IP settings.
 An asterisk (*) marks the default interface.

```
info
```
 Displays version.

```
ls
```
 Lists available files of mounted SHFS volume.

```
lsof
```
 Lists currently opened files and their reference counters.

```
lsvbd
```
 Lists available virtual block devices.

```
mallinfo
```
 Displays heap memory allocation information.

```
mount [VBD ID]...
```
 Mounts an SHFS volume. Multiple devices can be passed to the command.
 In this case, mount will search for SHFS volumes an all devices
 and will mount the first valid one. This is also required when multi-member
 volumes shall be mounted.

```
prefetch [FILE]
```
 Prefetches FILE into the disk block cache.

```
reboot
```
 Reboots system.

```
remount
```
 Re-mounts the currently mounted SHFS volume.

```
repeat [TIMES] [DELAY] [COMMAND] [[ARGS]]...
```
 Executes COMMAND TIMES-times. DELAY specifies a delay in ms between the
 executions. If a single COMMAND execution interation returns something less
 than 0, repeat exists immediately by returning this error code.

```
shfs-info
```
 Displays information about currently mounted SHFS volume.

```
stats
```
 Lists collected access statistics of files.

```
suspend
```
 Suspends system.

```
time [COMMAND] [[ARGS]]...
```
 Executes COMMAND while measuring its execution time.

```
umount
```
 Un-mounts the currently mounted SHFS volume.

```
uptime
```
 Displays system uptime.

```
who
```
 Lists active shell sessions.

```
xargs [COMMAND] [[ARGS]]...
```
 Executes COMMAND for each ARG.
