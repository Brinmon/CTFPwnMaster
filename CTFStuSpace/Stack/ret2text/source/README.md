-fno-stack-protector   canary
-z execstack 		NX
-z norelro 		RELRO
-no-pie		pie

# question_1.c
溢出覆盖相邻变量，启动后门逻辑getshell

# question_2.c
溢出覆盖返回地址，调用后门函数getshell