#include "global.h"
#include <time.h>
#include <math.h>
#include <random>

void display_sentence(char *cipher){
   printf("cipher:\n");
   for(int i=0;i<64;i++)
      printf("%d ", cipher[i]);
   printf("\n");
}
int main(){
   char keys[17][48];
   char cipher[64]; // cipher text

   srand((unsigned int)time(NULL));
   for (int i = 0; i < 64; i++)
	   K[i] = rand() % 2;
   construct_key_schedule(K,keys); // construct key schedule

   //construct_key_schedule(K, keys); // K is original 64bit key
   des_encrypt(M, keys, cipher);
   display_sentence(cipher);
}
