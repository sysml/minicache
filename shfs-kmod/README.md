# SHFS linux port

This is a poqrt of the "Simple Hash File System" to linux kernel 3.16.

SHFS is experimental, so it is highly recommended to run it inside an
isolated sandbox environment such as a virtual machine or dedicated
test computer.

To build the module run:
```
 # cd shfs-kmod
 # make -C <path_to_kernel_3.16_sources> M=$PWD
```

When mounted, filesystem shows two folders under the root directory:
"hashes" and "names". The latter one contains the symbolic links to
the files inside the first one:
```
 # ls /mnt/names -la
 total 0
 drwxrwxrwx    1 root     root             1 Jan  1  1970 .
 drwxrwxrwx    1 root     root             1 Jan  1  1970 ..
 lr--r--r--    1 root     root             1 Jan  1  1970 bigrnd -> ../hashes/a478133e09e414c3a7e680fe574338864db548adc371c55616c4c79edf016c52
```
