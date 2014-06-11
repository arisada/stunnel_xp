#include <openssl/rand.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <wait.h>

int getpid(){
	return 31337;
}

void print_hex(const unsigned char *buffer, size_t s){
	int i;
	for(i = 0; i< s; ++i){
		printf("%.2hhx",buffer[i]);
	}
	printf("\n");
}

int main(int argc, char **argv){
	int pid;
	unsigned char buffer[20];
	RAND_bytes(buffer, sizeof(buffer));
	pid = fork();
	if(pid != 0)
		wait(NULL);
	memset(buffer, 0, sizeof(buffer));
	RAND_bytes(buffer, sizeof(buffer));
	print_hex(buffer, sizeof(buffer));	
	return 0;
}
