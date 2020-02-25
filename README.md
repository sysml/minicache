MiniCache
=========

What is MiniCache?
------------------

MiniCache is a content cache/web server based on Mini-OS. It follows the
minimalistic and single-purpose VM idea, alias Unikernel. MiniCache servers
files via HTTP, provides a tiny telnet shell server (µShell) for management,
and comes with an object store system called SHFS (Simple Hash Filesystem).


Building MiniCache
------------------

### Preparations
It is recommended that you create a target directory first (e.g., ~/workspace).
It will be used to store all required sources and builds for MiniCache.

    export WORKSPACE=$HOME/workspace
    mkdir -p $WORKSPACE
    cd $WORKSPACE

I recommend to add this export line to your shell profile (e.g., via .bashrc if
you are using bash).


### Download and Build Xen (here: 4.4)
Please follow Xen's build instructions - it should be something like the
following:

    git clone git://xenbits.xen.org/xen.git
    cd xen
    git checkout stable-4.4
    ./configure
    make xen tools
    cd ..

Note: If Xen is not installed on your system yet, please install it as well.
You might need to restart your computer.
After that, please ensure that you set the following environment variables set
(I also recommend to add this to your shell profile):

    export XEN_ROOT=$WORKSPACE/xen


### Download dependencies
Our toolchain is required to comile and link the MiniCache VM binary:

    git clone git://github.com/sysml/toolchain.git

Also, Mini-OS, the base OS for MiniCache, is required:

    git clone git://github.com/sysml/mini-os.git

After that, please ensure that you set the following environment variables
(I also recommend to add this to your shell profile):

    export TOOLCHAIN_ROOT=$WORKSPACE/toolchain
    export MINIOS_ROOT=$WORKSPACE/mini-os


### Build toolchain
Please follow the build procedure as described in 'toolchain/README'.
In principle it should be:

    cd toolchain
    make
    cd ..


### Download and Build MiniCache
#### Clone the MiniCache repository

    git clone git://github.com/sysml/minicache.git
    cd minicache

#### Configure (optional)
You can configure your build by enabling/disabling features in MiniCache.
This can be done by placing a file called .config.mk in your MiniCache
source directory. You can have a look in Config.mk which is the managed
configuration file (do not change this one).

#### Build

    make

Note: Building for different targets than mini-os can be achieved by
specifying the ```TARGET``` variable to make (see ```Makefile```).


#### Build SHFS Tools
The SHFS tools are required to create and maintain SHFS filesystems.
Please read ```shfs-tools/README.md``` for more details.


### Getting Started

#### Create a Xen Guest Configuration
In order to boot MiniCache, create a Xen guest configuration file. You can use the
following example as a basis and save it under ```minicache.cfg```:

    kernel        = 'build/minicache_x86_64'
    vcpus         = '1'
    memory        = '64'

    name          = 'minicache'
    extra         = '-i 192.168.0.2/24 -g 192.168.0.1 -d 192.168.0.1 -b 51712'

    vif           = [ 'mac=00:16:3e:ba:be:12,bridge=virbr0' ]

    # Here, one FS image and 3 RAM-based drives
    disk          = [ 'file:/root/workspace/minicache/demofs.img,xvda,w' ]

For now, just a single VIF is supported by MiniCache but you can assign
multiple virtual disks. Use ```phy:/path/to/dev'``` when you use a block
device as virtual disk and ```file:/path/to/image'``` when you use an
image file.
The `extra` option in the configuration specifies the parameters
that you pass to the guest. Possible options for MiniCache are listed
in the last paragraph.

#### Create a Filesystem
Creating a filesystem for MiniCache can be done with ```shfs_mkfs```
and ```shfs_admin```. In the following we will create a filesystem image
file with the files in the ```demofs/``` directory:

First we create an empty image file (with 128 MB disk size):

    dd if=/dev/zero of=demofs.img bs=1M count=128

Then we format it with SHFS:

    shfs-tools/shfs_mkfs demofs.img
    
Afterwards, we copy some files to it:
 
    shfs-tools/shfs_admin -a demofs/index.html  -m text/html    demofs.img
    shfs-tools/shfs_admin -a demofs/logo.png    -m image/png    demofs.img
    shfs-tools/shfs_admin -a demofs/favicon.ico -m image/x-icon demofs.img

When the copying is done, we should mark ```index.html``` as the default
file. For this purpose we need to figure out what is the current hash digest
for this file (since file names are actually hash digest in SHFS).
This can be done by using the integrated ls command of ```shfs_admin```:

    shfs-tools/shfs_admin -l demofs.img

Remember the corresping digest and pass it to the set-default command
of ```shfs_admin```:

    shfs-tools/shfs_admin -d 1e833c10400fd4cd5acf6cf73764a35d66eb68f627a332e129b246ca39df1e55 demofs.img

When you list the filesystem content again, this file should have the
flag ```D``` set.

#### Boot the VM
The VM is booted with the xl command:

    xl create -c minicache.cfg


When your networking setup is correct, you should be able now to see
the demo page in a browser.

    http://192.168.0.2/

You should also be able to use telnet to login to the embedded shell
of MiniCache:

    telnet 192.168.0.2

...and ping should work, too:

    ping 192.168.0.2


### MiniCache Parameters

    -s [sec]               Start-up delay in seconds (default is 0)
    -i [IPv4/Route prefix] Host IP address in CIDR notation
                           (if not specified, DHCP client is enabled)
    -g [IPv4]              Gateway IP address
    -d [IPv4]              Primary DNS server
    -e [IPv4]              Secondary DNS server
    -a [hwaddr]/[IPv4]     Static ARP entry
                           (multiple tokens possible)
    -b [VBD ID]            Automount filesystem from VBD ID
                           (multiple tokens possible;
                            disables vbd auto detection;
                            example IDs: 51712=xvda, 51728=xvdb,
                            51744=xvdc, 51760=xvdd)
    -h                     Disable XenStore control trigger
                           (see: ctltrigger)
    -x [VBD ID]            Device for stats export
    -c [num]               Max. number of simultaneous HTTP connections
    -P                     Prefetch: Read all SHFS entries to the
                            cache after boot completed
