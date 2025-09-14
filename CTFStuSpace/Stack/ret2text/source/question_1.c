//gcc ./question_1.c -o pwn1 -O0

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
char sh[]="/bin/sh";
int init_func(){
    setvbuf(stdin,0,2,0);
    setvbuf(stdout,0,2,0);
    setvbuf(stderr,0,2,0);
    return 0;
}

int func(char *cmd){
	system(cmd);
	return 0;
}

int main(){
	init_func();
	char a[8] = {};
	char b[8] = {};
    //char a[1] = {'b'};
	puts("input:");
	gets(a);  
	printf("%s",a);
	
	if(b[0]=='a'){ 
		func(sh);
	}
    return 0;
}
