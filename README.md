Overview of the MIPS-LK TEE project
===================================

Updated: Mar 23, 2018.

The [mips-lk](https://github.com/MIPS/mips-lk) repository belongs to the
[MIPS-TEE](https://github.com/MIPS/mips-tee) project.

The MIPS TEE project combines the L4Re Hypervisor, MIPS-LK Trusted Execution
Environment (TEE) and Linux Rich Execution Environment (REE) to implement a TEE
meeting the requirements of the GlobalPlatform (GP) TEE API Specifications.

- [GlobalPlatform TEE Device Specifications](https://www.globalplatform.org/specificationsdevice.asp)

Refer to the top level MIPS-TEE repository for

- MIPS TEE overview and installation instructions: [README](https://github.com/MIPS/mips-tee/blob/master/README.md)
- REE build instructions: [HOWTO-ree](https://github.com/MIPS/mips-tee/blob/master/ree/HOWTO-ree.md).

Refer to this current repository for

- TEE and L4Re Hypervisor build instructions: [HOWTO-tee](./HOWTO-tee.md)

The MIPS-LK TEE project expands on the LK (LittleKernel), Trusty and OP-TEE
code bases.

- [LK](https://github.com/littlekernel/lk)
- [Trusty](https://source.android.com/security/trusty/)
- [OP-TEE](https://github.com/OP-TEE)


Supported GlobalPlatform TEE APIs
==================================

This implementation supports the following APIs from the GP TEE Internal Core
API Specification v.1.1.2 (GPD_SPE_010):

- Trusted Core Framework API
    - TA Interface
    - Property Access Functions
    - Panics
    - Internal Client API
    - Memory Management Functions
- Trusted Storage API
    - API for Persistent Object is not yet implemented
- Cryptographic Operations API
- Time API
    - Persistent Time API is not yet implemented
- TEE Arithmetical API


MIPS-LK TEE Components and Overview
===================================

GP TEE communication is based on a REE Client Application (CA) requesting an
operation from a Trusted Application (TA) and the TA sending back a response.
This communication flows through the Session Manager (SM) component in the TEE.
REE CA requests are made through the GP TEE Client API and in the case of TAs
which are themselves clients, TA client requests to other TAs are made through
the GP Internal Client API. All the internal TEE communication is based on the
Trusty IPC API.

The following components and directories contain the code providing the TEE
system functionality.

- ./documentation:

  Refer to this [TEE system diagram](./documentation/TEE_system_diagram.txt)
  for an overview. For more information about REE to TEE communications refer
  to the [REE TEE link diagram](./documentation/REE_TEE_link_diagram.txt).

- ./app/ta:

  Each Trusted Application (TA) is linked with libutee and communicates with
  the Session Manager through the GP TEE Internal Core API and Trusty-TEE
  syscalls.

- ./app/tee/sess_mngr:

  Session Manager (SM) is a privileged TA running in user space. It implements
  GP TEE Internal Core API functionality related to session management, client
  application (CA) communication, and TA to TA communication.

- ./lib/lib/libutee:

  The libutee library is the user space portion of the GP TEE Internal Core API
  implementation. It uses Trusty-TEE syscalls to communicate with the Session
  Manager and the tee kernel library. The main() function of a TA is provided
  by libutee.

- ./trusty/lib/tee:

  The tee library is the kernel space portion of the GP TEE Internal Core API
  implementation.


Trusted Application description
===============================

Each MIPS-LK TEE trusted application requires:

- a manifest.c file defining TA's UUID and basic properties
- a .c file implementing the GP Trusted Core Framework API TA Interface entry
  point functions
- rules.mk file defining the build rules
- that it be linked with libutee to provide it with the main() start function.
