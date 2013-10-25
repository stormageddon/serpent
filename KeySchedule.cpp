#include <iostream>
#include <math.h>
#include <vector>
#include "KeySchedule.h"
using namespace std;




KeySchedule::KeySchedule(){
  
  /*
  ip = {0, 32, 64, 96, 1, 33, 65, 97, 2, 34, 66, 98, 3, 35, 67, 99,
  	4, 36, 68, 100, 5, 37, 69, 101, 6, 38, 70, 102, 7, 39, 71, 103,
  	8, 40, 72, 104, 9, 41, 73, 105, 10, 42, 74, 106, 11, 43, 75, 107,
	12, 44, 76, 108, 13, 45, 77, 109, 14, 46, 78, 110, 15, 47, 79, 111,
	16, 48, 80, 112, 17, 49, 81, 113, 18, 50, 82, 114, 19, 51, 83, 115,
	20, 52, 84, 116, 21, 53, 85, 117, 22, 54, 86, 118, 23, 55, 87, 119,
	24, 56, 88, 120, 25, 57, 89, 121, 26, 58, 90, 122, 27, 59, 91, 123,
	 28, 60, 92, 124, 29, 61, 93, 125, 30, 62, 94, 126, 31, 63, 95, 127};
  */

  for (int i = 0; i <= 127; i++ ){
    ip[i] = (32*i) & 127;
    cout << ip[i] << endl;
  }

  k3, k2, k1, k0 = 0;  
  key_size = -1;
}

void KeySchedule::setKey (unsigned char user_key[]){
  
  if (sizeof(user_key) == 128){
    cout << sizeof(user_key) << endl;
    cout << "size of user key / user key *" << endl;
    cout << sizeof(user_key) / sizeof(user_key[0]) << endl;
    key_size = 16;
    
    k3 = 2147483648;
    
    for (int i = 0; i<64; i++){
      k1 ^= user_key[i] << (63-i);
      k0 ^= user_key[i+64] << (63-i);
    }
  }
  else if (sizeof(user_key) == 192){
    
    key_size = 24;
    
    k3 = 2147483648;
    
    for (int i = 0; i<64; i++){
      k2 ^= user_key[i] << (63-i);
      k1 ^= user_key[i+64] << (63-i);
      k0 ^= user_key[i+128] << (63-i);
    }
  }
  else if (sizeof(user_key) == 256){
    
    key_size = 32;

      for (int i = 0; i<64; i++){
	k3 ^= user_key[i] << (63-i);
	k2 ^= user_key[i+64] << (63-i);
	k1 ^= user_key[i+128] << (63-i);
	k0 ^= user_key[i+192] << (63-i);
      }
    }else {
      cout << "The key has not been set. " << endl;
      cout << "Serpent takes a 128, 192, or 256 bit key. " << endl;
    }
  }

  /**
   * Returns this block cipher's key size in bytes.
   *
   * @return  Key size.
   */
int KeySchedule::keySize (){
      
    if (key_size == -1){
      cout << "Keysize has not been set; returning 0." << endl;
      return 0;

    }else{
      return key_size;
    }
}

int main(){
  cout << "I'm running!!! " << endl;
  
}

   

  
