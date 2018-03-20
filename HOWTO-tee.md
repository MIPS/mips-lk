Running MIPS LK TEE and REE on the L4Re Hypervisor
==================================================

Updated: Mar 23, 2018.

You need to build three components to run the MIPS LK Trusted Execution
Environment inside two Virtual Machines. Build the TEE last after building
L4Re and REE.

  - Hypervisor: L4Re kernel and userland with the uvmm Virtual Machine
    Monitor package
  - REE: Linux with Mips virtualization patches and a root file system (both
    built using Buildroot)
  - TEE: mips-lk with mips-virt platform


Prerequisites
=============

Install mips MTI toolchains and add to the PATH environment variable.

- mips-mti-elf toolchain (bare metal variant for little kernel)
- mips-mti-linux-gnu toolchain (for building L4Re and Linux)

The MIPS MTI codescape toolchains (suitable for mips32 R2-R5 instruction sets)
can be obtained here:

    wget https://codescape.mips.com/components/toolchain/2016.05-06/Codescape.GNU.Tools.Package.2016.05-06.for.MIPS.MTI.Bare.Metal.CentOS-5.x86_64.tar.gz
    wget https://codescape.mips.com/components/toolchain/2016.05-06/Codescape.GNU.Tools.Package.2016.05-06.for.MIPS.MTI.Linux.CentOS-5.x86_64.tar.gz

For mips-lk projects the toolchain is specified using the TOOLCHAIN_PREFIX
variable defined in the project makefile. The default can be overridden with an
environment variable if necessary.

    # optionally override the mips-lk project toolchain prefix
    export TOOLCHAIN_PREFIX=mips-mti-elf-

For building L4Re components the toolchain is specified using the CROSS_COMPILE
environment variable. Typically this value is stored in a local make config
file as explained below.

- dtc, the device tree compiler:
  In Ubuntu/Debian: `sudo apt-get install device-tree-compiler`


Platforms
=========

The MIPS TEE project requires a platform which supports the MIPS Virtualization
(VZ) architecture module. The VZ module is used by the L4Re hypervisor to
support running the REE and TEE operating systems in isolation in separate
virtual machines on the same CPU.

The IASim simulator from MIPS (based on Open Virtual Platforms from Imperas)
does support VZ.  IASim version 3.7.2 is known to work.  For access to IASim,
please contact MIPS Sales.

The Baikal-T1 SoC from Baikal Electronics, based on the MIPS P5600 CPU,
supports VZ and is a supported hardware platform.

QEMU does not support the VZ feature and as such is not suitable for running
the full MIPS TEE project with L4Re hypervisor.


Getting the L4Re Hypervisor source code
=======================================

If you were following mips-tee/README and/or used script
mips-tee/scripts/do-mips-tee-mrconfig you can skip this part.

A recent version of the L4Re and Fiasco source code from the
Kernkonzept svn repository is required. Note that L4Re needs
to be compiled  with the mips-mti-linux-gnu compiler. To make
sure the right compiler is used, the instructions below
configure the compiler in the Makeconf.local file.

To check the source out into $L4RE_DIR (l4re) use the repomgr script:

    cd <mips_tee_directory>
    # checkout Fiasco kernel and L4Re with all the necessary packages
    # specify the `-l` option to set the install directory
    svn cat https://svn.l4re.org/repos/oc/l4re/trunk/repomgr | perl - init https://svn.l4re.org/repos/oc/l4re -l l4re mips_tee
    cd l4re
    export L4RE_DIR=`pwd`


Building L4Re Hypervisor
========================

This step will configure and build the L4Re hypervisor kernel and userland.
These instructions are meant to supplement build instructions and documentation
provided by the L4Re project itself.

In this step it is not necessary to package and build the final runnable L4Re
bootstrap image as that will be done after all the other system components have
also been built.

Configure the L4Re kernel. For running on IASim:

    cd $L4RE_DIR/kernel/fiasco
    make B=../../build-kernel T=mips-malta-mp

For the Baikal board use `T=mips-baikal-mp`.

Change into the build directory and configure the build using `make config`.
Enable virtualization and adjust the CPU frequency if the defaults do not match
the platform. Optionally disable the built-in kernel debugger JDB (CONFIG_JDB).
Compile the kernel:

    cd ../../build-kernel
    echo CROSS_COMPILE=mips-mti-linux-gnu- > Makeconf.local
    # enable kernel virtualization CONFIG_CPU_VIRT
    # modify CPU Frequency if necessary
    # optionally disable the built-in JDB debugger (CONFIG_JDB)
    make config
    make -j4

Next compile the L4Re userland (which includes uvmm) specifying platform
`PT=malta` or `PT=baikal_t` and optionally review the default platform build
options.

    cd $L4RE_DIR/l4
    CROSS_COMPILE=mips-mti-linux-gnu- make B=../build-l4re T=mips PT=malta
    cd ../build-l4re
    echo CROSS_COMPILE=mips-mti-linux-gnu- > Makeconf.local
    # optionally review the build configuration
    make config
    make -j4

Note using `make -j<n>` can speed up the build but may result in build failures
because of inter-package dependencies. It may be necessary to repeat the make
again (possibly with `make -k` if necessary). After this stage the bootstrap
package will still have to be rebuilt but the other packages should build
successfully.

Before building the bootstrap image make sure the L4Re kernel can be found:

    echo MODULE_SEARCH_PATH += $L4RE_DIR/build-kernel >> $L4RE_DIR/l4/conf/Makeconf.boot

For the MIPS LK TEE project the L4Re bootstrap image is built in a later step.
For more information please skip to section "Building and Running MIPS TEE"
below.

Optionally, to test that the L4Re kernel and userland built properly, compile
and run a bootstrap image for the hello world example:

    cd $L4RE_DIR/build-l4re
    make PT=malta E=hello elfimage

Now you can run the final image `$L4RE_DIR/build-l4re/images/bootstrap.elf`
on IASim.

To create a final bootstrap image for the Baikal board run:

    make PT=baikal_t E=hello rawimage

The bootable image is then here: `$L4RE_DIR/build-l4re/images/bootstrap.raw`


Building Linux REE and root file system
=======================================

If linux and rootfs are already built (as described in ree/HOWTO-ree) this part
can be skipped.

When building Linux for use as a L4Re guest VM Linux must be patched to support
the Mips virtual platform mach_virt_defconfig.

Refer to ree/HOWTO-ree for using buildroot to compile Linux for the virtual
platform with REE support and a rootfs for the Linux guest.

To build Linux manually be sure to apply the patch for the Mips virtual
platform:

    patch -Np1 -i $L4RE_DIR/l4/pkg/uvmm/configs/guests/Linux/mips/0001-MIPS-Add-virtual-platform-linux-4.4.patch

And build Linux the usual way:

    make O=$LINUX_BUILDDIR ARCH=mips mach_virt_defconfig
    make O=$LINUX_BUILDDIR ARCH=mips CROSS_COMPILE=mips-mti-linux-gnu- -j4


Configuring the L4Re Bootstrap Image Components
===============================================

For the MIPS LK TEE project the `do-l4re-mips-virt` build script takes care of
configuring the bootstrap image components. This section explains in detail how
an L4Re project is configured.

The bootstrap image contains the Fiasco kernel for the hypervisor, L4Re
userland and all other required modules or files.

The environment variable MODULES_LIST specifies the modules.list configuration
file which defines the contents of images and their entrypoints. For this
project the make command specifies:

    MODULES_LIST=$MIPS_LK/l4re-boot/modules.list

The entrypoint is listed in modules.list and specifies all the modules which
the image requires. i.e. `entry mips_tee` would be specified as `E=mips_tee` on
the bootstrap make command line.

The environment variable MODULE_SEARCH_PATH, as well as the Makeconf.boot and
Makeconf.local files, specify the paths to search for the binaries and files.

Amongst these modules is a *.ned startup script which is executed by
the L4Re hypervisor to start the VMs with the necessary parameters. This
startup script also contains the Linux kernel cmdline bootargs which can be
modified if required.

    bootargs = "console=hvc0 earlyprintk=1"

If any of the binary module names are changed (e.g. linux, dts, or root
file system) the modules list and startup script need to be updated prior to
rebuilding the bootstrap image.


Regenerating Device Tree configuration for the VM compartments
==============================================================

The TEE and REE VMs are configured via pre-compiled device tree descriptions
in the $MIPS_LK/l4re-boot directory. The l4re-boot/modules.list and *.ned files
specify which dtb files are used.

If you want to change the dtb configurations, modify the corresponding .dtb.src
files in l4re-boot. Then change to l4re-boot and rebuild the files with:

    make dtb

The `./lk/scripts/do-l4re-mips-virt` script referenced below also rebuilds the
dtb files.


Building the MIPS TEE image: the final step
===========================================

Before running this final build step, ensure that the REE and L4Re component
build steps have been completed. This final step will build mips-lk and package
all the other components together.  This final build step must be repeated
whenever any of the REE, TEE or L4Re hypervisor components change.

To build mips-lk for the L4Re hypervisor use the LK mips-virt platform. To
build a project, run `do-l4re-mips-virt` from the mips-lk/ top-level directory:

    cd <mips_lk_directory>
    export TOOLCHAIN_PREFIX=mips-mti-elf-
    ./lk/scripts/do-l4re-mips-virt -p mips-trusty-svr

Run `do-l4re-mips-virt -h` for a list of options which change the default
location of the kernel image, l4re build directory and LK project.
Run `make list` to display a list of all LK projects.

When the build is successful, a bootable image can be found under
build-*/l4reboot.image. It contains the hypervisor, MIPS TEE and Linux REE and
will boot the Linux and the MIPS TEE project in two separate VMs.

To build an image for the Baikal platform use the -t parameter:

    ./lk/scripts/do-l4re-mips-virt -t baikal -l $L4RE_DIR -p mips-trusty-svr


MIPS TEE project descriptions
=============================

- The mips-trusty-svr mips-lk project must be run with IASim or on a VZ capable
  hardware platform. It populates the TEE with a few sample TAs which can be
  called from the Linux REE with the `/usr/bin/starter` program.

  Dependencies: TEE, REE and L4Re
  It requires that the Buildroot rootfs contain the BR2_PACKAGE_LIBTEEC package
  and the BR2_PACKAGE_TEST_STARTER_CA package corresponding to
  mips-tee-test/clientapps/test_ta_starter.

- The mips-ree-xtest mips-lk project must be run with IASim or on a VZ capable
  hardware platform. It populates the TEE with TAs from the xtest suite which
  can be called from the Linux REE with the `/usr/bin/xtest` program.

  Dependencies: TEE, REE and L4Re
  It requires that the Buildroot rootfs contain the BR2_PACKAGE_LIBTEEC package
  and the BR2_PACKAGE_XTEST package (and optionally the BR2_PACKAGE_XTEST_GP)
  corresponding to mips-tee-test/xtest.

- The mips-malta-teetest mips-lk project is a sample project that runs on QEMU.
  It builds a few sample TAs and only runs the TEE part of the MIPS TEE
  project, the Linux REE part is not used.  The image is not loaded into a VM,
  it is run directly.  The project can serve as a template for convenient
  development of TA code without having to debug code running in a hypervisor
  VM container as is the case with the full MIPS TEE projects.

  Dependencies: TEE


Running MIPS TEE on the IASim platform
======================================

The `mipssim.sh` script is provided for running the final image in IASim.
Please refer to the IASim Getting Started Guide for installation instructions
and environment variable settings.  The `mipssim-p5600.cfg` configuration file
is used by the script to define the MIPS platform which IASim will emulate. Run
an elf image in IASim as such:

    cd <mips_lk_directory>
    ./mipssim.sh build-mips-trusty-svr/l4reboot.image


Tips Running MIPS TEE
=====================

After the two VMs are up and running, the L4Re "cons" console server command
line can be reached using the "Ctrl-E ." sequence.  Use "Ctrl-E 1" and
"Ctrl-E 2" to switch between the virtual console of the two VMs.  Type help for
more "cons" commands.

When the L4Re fiasco built-in kernel debugger JDB is enabled, press ESC to
enter into the debugger, g to continue, and h for help.

The default Linux user and password are set during the ree/HOWTO-ree build
steps.
