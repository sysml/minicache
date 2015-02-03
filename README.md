MiniCache
=========

What is MiniCache?
------------------

MiniCache is a content cache/web server based on Mini-OS. It follows the
minimalistic and single-purpose VM idea. MiniCache servers files via HTTP,
provides a tiny telnet shell server (µShell) for management, and comes with
SHFS (Simple Hash Filesystem) support.


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
Note: For ARM builds you might need different Xen sources (e.g., https://github.com/talex5/xen.git)
or you might have to use a different branch.

After that, please ensure that you set the following environment variables set
(I also recommend to add this to your shell profile):

    export XEN_ROOT=$WORKSPACE/xen


### Download and Build toolchain
The toolchain is required to comile and link the MiniCache VM binary. A
toolchain having lightweightIP 1.4.1 (or newer) is required.

    git clone git@repos:oss/toolchain.git
    cd toolchain
    git checkout skuenzer/lwip-latest
    cd ..

Note: Please checkout the branch skuenzer/lwip-latest-arm32 when you build for ARM.

Please follow the build procedure as described in 'toolchain/README'.
In principle it should be:

    make

For ARM it should be

    make XEN_TARGET_ARCH=arm32

After that, please ensure that you set the following environment variables
(I also recommend to add this to your shell profile):

    export TOOLCHAIN_ROOT=$WORKSPACE/toolchain

### Download mini-os

    git clone git@repos:oss/mini-os.git
    cd mini-os
    git checkout skuenzer/lwip-latest
    cd ..

Note: Please checkout the branch skuenzer/lwip-latest-arm32 when you build for ARM.

After that, please ensure that you set the following environment variables set
(I also recommend to add this to your shell profile):

    export MINIOS_ROOT=$WORKSPACE/mini-os

### Download and Build Cosmos (optional, x86_64 only)
Cosmos is used to instiate the MiniCache VM. However, you can also use the
traditional xl tools from Xen but netmap/vale will not be supported then.

    git clone https://github.com/cnplab/cosmos.git

Please follow the build procedure as described in 'cosmos/README.md'.
I recommend to build cosmos with 'xl'.

Additionally, I recommend to link the cosmos binary to a directory that is
included in the command search of your shell:

    ln -sv $WORKSPACE/cosmos/dist/bin/cosmos /usr/local/bin/


### Download and Build MiniCache
#### Clone the MiniCache repository

    git clone git@repos:skuenzer/minicache.git
    cd minicache

#### Configure (optional)
You can configure your build by enabling/disabling features in MiniCache.
This can be done by placing a file called .config.mk in your MiniCache
source directory. You can have a look in Config.mk which is the managed
configuration file (do not change this one).
For instance, a netmap-based netfrontend is activated by adding the
following line to .config.mk:

    ## vif
    CONFIG_NETMAP                   = y

Mini-OS's standard netfront (vif) is enabled with the following settings:

    ## vif
    CONFIG_NETMAP                   = n

#### Build

    make

Note: If you want to build for ARM, call the following make command instead:

    make ARCH=arm32

Note: Multi-threaded building (-j option) is not working at the moment.

#### Build SHFS Tools
The SHFS tools are required to create and maintain SHFS filesystems.
Please read 'shfs-tools/README.md' for more details.


### Getting Started
In order to boot MiniCache, create a Xen VM configuration file. You can use the
following example as a basis:

    #!/usr/local/bin/cosmos load

    kernel        = './build/minicache_x86_64'
    builder       = 'linux'
    vcpus         = '1'
    memory        = '16'

    name          = 'minicache'

    vif           = [ 'mac=00:16:3e:ba:be:12,bridge=expbr0' ]

    # Here, one FS image and 3 RAM-based drives
    disk          = [ 'file:/root/workspace/minicache/demofs.img,xvda,w',
                      'phy:/dev/ram13,xvdb,w',
                      'phy:/dev/ram14,xvdc,w',
                      'phy:/dev/ram15,xvdd,w' ]

Thanks to Cosmos (when build with xl), you can set the executable bit to
this file and instantiate the VM like a regular binary that is executed
in Domain-0. The parameters are passed as kernel parameters to the image:

    chmod a+x minicache
    ./minicache -i 192.168.0.2/24 -g 192.168.0.1

Otherwise, use the `extra` option in the Xen Domain configuration file to
specify the kernel parameters:

    extra         = '-i 192.168.0.2/24 -g 192.168.0.1'


### MiniCache Parameters

    -s [sec]               Startup delay in seconds (default is 0)
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
