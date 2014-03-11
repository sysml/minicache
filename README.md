# MiniCache

## What is MiniCache?

MiniCache is a content cache server based on Mini-OS. It follows the
minimalistic and single-purpose VM idea. MiniCache servers files via HTTP,
provides a tiny telnet shell server (µShell) for management, and comes with
SHFS support.

## Building MiniCache

### Preparations
It is recommended that you create a target directory first (e.g., ~/workspace).
It will be used to store all required sources and builds for MiniCache.

    export WORKSPACE=$HOME/workspace
    mkdir -p $WORKSPACE
    cd $WORKSPACE

I recommend to add this export line to your shell profile (e.g., via .bashrc if
you are using bash).


### Download and Build Xen (here: 4.2.3)
Please follow Xen's build instructions - it should be something like the
following:

    wget http://bits.xensource.com/oss-xen/release/4.2.3/xen-4.2.3.tar.gz
    tar -xvf xen-4.2.3
    cd xen-4.2.3
    ./configure
    make world
    cd ..

Note: If Xen is not installed on your system yet, please install it as well.
You might need to restart your computer.

After that, please ensure that you set the following environment variables set
(I also recommend to add this to your shell profile):

    export XEN_VER=4.2.3   # replace this number with your downloaded Xen version
    export XEN_VERSION=$XEN_VER
    export XEN_ROOT=$WORKSPACE/xen-$XEN_VER


### Download and Build toolchain
The toolchain is required to comile and link the MiniCache VM binary. A
toolchain having lightweightIP 1.4.1 is required.

    git clone git@repos:joao/toolchain.git
    cd toolchain
    git checkout feature/lwip-1.4.1
    cd ..

Please follow the build procedure as described in 'toolchain/README'.


### Download and Build Cosmos (optional)
Cosmos is used to instiate the MiniCache VM. However, you can also use the
traditional xl tools from Xen but netmap/vale will not be supported then.

    git clone git@repos:joao/cosmos.git

Please follow the build procedure as described in 'cosmos/README.md'.

Additionally, I recommend to link the cosmos binary to a directory that is
included in the command search of your shell:

    ls -sv $WORKSPACE/cosmos/build/bin/cosmo /usr/local/bin/


### Download and Build MiniCache
#### Clone the MiniCache repository

    git clone git@repos:skuenzer/minicache.git
    cd minicache
    git submodule init
    git submodule update
    cd ..

#### Configure (optional)
You can configure your build by enabling/disabling features in MiniCache's
Makefile. For instance, a netmap frontend (via nmwrap) is activated by setting
the following symbols:

    CONFIG_NETMAP_XENBUS = y
    CONFIG_NETMAP = y
    CONFIG_NETMAP_API = 4
    CONFIG_NETFRONT = n
    CONFIG_NETFRONT_NETMAP2 = n
    CONFIG_NMWRAP = y

Mini-OS's standard netfront (vif) is enabled with the following settings:

    CONFIG_NETMAP_XENBUS = n
    CONFIG_NETMAP = n
    CONFIG_NETFRONT = y
    CONFIG_NETFRONT_NETMAP2 = n
    CONFIG_NMWRAP = n

#### Build

    cd minicache
    make -j8 all
    cd ..

#### Build SHFS Tools
The SHFS tools are required to create and maintain SHFS filesystems.
Please read 'shfs-tools/README.md' for more details.


### Getting Started

In order to boot MiniCache, create a Xen VM configuration file. You can use the
following example as a basis:

    #!/usr/local/bin/cosmos load

    kernel        = './build/minicache_x86_64.gz'
    builder       = 'linux'
    vcpus         = '1'
    memory        = '32'

    name          = 'minicache'

    vif           = ['mac=00:16:3e:ba:be:12,bridge=expbr0' ]

    # One FS image and 3 RAM-based drives
    disk          = [ 'file:/root/workspace/minicache/demofs.img,xvda,w',
                      'phy:/dev/ram13,xvdb,w',
                      'phy:/dev/ram14,xvdc,w',
                      'phy:/dev/ram15,xvdd,w' ]

Thanks to Cosmos, you can set the executable bit to this file and instantiate
the VM like a regular binary that is executed in Domain-0:

    chmod a+x minicache
    ./minicache
