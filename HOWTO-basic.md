Basic HOWTO for building a MIPS LK project
==========================================

Updated: Mar 23, 2018.

Follow these instructions for building a simple MIPS LK project.


Prerequisites
=============

- mips-mti-elf toolchain
- qemu-system-mipsel


Building and running
====================

To see a list of available projects run

    make list

To build and run a project, run the do-qemumips-malta script from the top-level
directory and use the '-p' flag to specify a project file..

    ./lk/scripts/do-qemumips-malta -p mips-malta-test

The executable is in the build-mips-malta-test directory.


Debugging
=========

The do-qemumips-malta script will start qemu-system-mipsel and pass all flags
after '--' to QEMU. Pass -S to wait for a connection on port tcp:1234 and
connect with gdb.

    ./lk/scripts/do-qemumips-malta -p mips-malta-test -- -S

Connect from gdb
    mips-mti-elf-gdb
    (gdb) target remote tcp::1234
    (gdb) file ./build-mips-malta-test/lk.elf
