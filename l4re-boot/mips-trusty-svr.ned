-- vi:ft=lua

local L4 = require "L4"
local l = L4.Loader.new({factory = L4.Env.factory, mem = L4.Env.user_factory})

---------- console

l.log_fab = l:new_channel()

l:start(
  {
    scheduler = l.sched_fab:create(L4.Proto.Scheduler, 0x40 + 10, 0x40, 1),
    log = L4.Env.log,
    caps = { cons = l.log_fab:svr() }
  }, "rom/cons -a -c vm-lnx")

----------- trusty protocol proxy for VM to VM virtio connection

local drvchan
local devchan
local DIRECT_ACCESS = '--with-direct-access'
local PROXIED_MEMORY = '--with-proxied-memory'

if arg[1] == PROXIED_MEMORY then

  -- more secure; proxied access to REE memory.
  drvchan = l:new_channel()
  devchan = l:new_channel()

  l:startv({
      log = { "proxy", "b" },
      caps = { dev = devchan, drv = drvchan:svr() }
  }, "rom/virtio-trusty-proxy")

elseif arg[1] == DIRECT_ACCESS then

  -- faster; directly mapped access to all REE memory.
  drvchan = l:new_channel()
  devchan = drvchan

else
  error("Must specify direct or proxied memory access for trusty protocol")
end

----------- shared memory

local teeshm = L4.Env.user_factory:create(L4.Proto.Dataspace, 10 * 1024 * 1024, 0, 10):m("rw")

----------- TEE VM

l:startv({
    log = { "vm-tee", "w", "key=1" },
    caps = {
      ram = L4.Env.user_factory:create(L4.Proto.Dataspace, 64 * 1024 * 1024, 0x3, 10):m("rws"),
      mon = l.log_fab:create(L4.Proto.Log, "mon-tee", "g"),
      viodev = devchan:svr(),
      teeshm = teeshm
    }
  }, "rom/uvmm", "-v", "-krom/lk.elf", "-drom/virt-mips-svr.dtb"
)

----------- Linux VM

l:startv({
    log = { "vm-lnx", "w", "key=2" },
    caps = {
      ram = L4.Env.user_factory:create(L4.Proto.Dataspace, 128 * 1024 * 1024, 0x3, 10):m("rws"),
      mon = l.log_fab:create(L4.Proto.Log, "mon-lnx", "g"),
      proxy = drvchan,
      teeshm = teeshm
    }
  }, "rom/uvmm", "-krom/vmlinux", "-rrom/busybox.rd",
     "-drom/virt-mips-dev-mipstee.dtb", "-cconsole=hvc0 earlyprintk=1"
)

