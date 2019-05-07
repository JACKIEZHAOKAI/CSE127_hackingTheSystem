#ifndef __SYSAPP_H__
#define __SYSAPP_H__

/*******************************************************
 CSE127 Project
 "system library" header file
 
            DO NOT MODIFY THIS FILE!!

 *******************************************************/

// this function checks the user password
// input:  
//      pass   - a null-terminated password string
// output:
//      0 if the password was incorrect
//      1 if the password was correct
//
int check_pass(char *pass);

// call this function when you have found the password.
// give it a correct password that you have found
// 
// this function calls exit() internally, so it will never 
// return
void hack_system(char *correct_pass);

#endif
