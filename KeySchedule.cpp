#include <iostream>
#include <bitset>
using namespace std;

class KeySchedule{

  int ip[64];
  int size;
  unsigned long long int k0;
  unsigned long long int k1;
  unsigned long long int k2;
  unsigned long long int k3;
  unsigned long int words[140];
  unsigned long long int subKeysUpper[33];
  unsigned long long int subKeysLower[33];
  static const long int phi = 2654435769;

public:

  KeySchedule(){
  
    /*The initial permutation. To be applied to the plaintext and keys.
      ip = {0, 32, 64, 96, 1, 33, 65, 97, 2, 34, 66, 98, 3, 35, 67, 99,
      4, 36, 68, 100, 5, 37, 69, 101, 6, 38, 70, 102, 7, 39, 71, 103,
      8, 40, 72, 104, 9, 41, 73, 105, 10, 42, 74, 106, 11, 43, 75, 107,
      12, 44, 76, 108, 13, 45, 77, 109, 14, 46, 78, 110, 15, 47, 79, 111,
      16, 48, 80, 112, 17, 49, 81, 113, 18, 50, 82, 114, 19, 51, 83, 115,
      20, 52, 84, 116, 21, 53, 85, 117, 22, 54, 86, 118, 23, 55, 87, 119,
      24, 56, 88, 120, 25, 57, 89, 121, 26, 58, 90, 122, 27, 59, 91, 123,
      28, 60, 92, 124, 29, 61, 93, 125, 30, 62, 94, 126, 31, 63, 95, 127};
    */

    for (int i = 0; i < 127; i++ ){
      ip[i] = (32*i) % 127;
    }
    ip[127] = 127;
  
    k3 = 0; 
    k2 = 0; 
    k1 = 0;
    k0 = 0;  

    size = -1;
  }

  /**
   * Sets the key used to generate the values of subKeys[].
   * Byte array of size 16, 24, or 32
   */
  void setKey (unsigned char userKey[]){
    
    if (size == -1){
      cout << "Keysize has not been set."<< endl;
      cout << "Call setKeySize(int n) with n = 128, 192, 256"<< endl;
      cout << "Key has not been set." << endl;
    }

    if (size == 16){
      k3 = (unsigned long long int)1<< 63;
      cout << "k3 here: " << k3 << endl;
      
      for (int i = 0; i<8; i++){
	k1 ^= ((long long int)userKey[i] << (56 - (8*i)));
	k0 ^= ((long long int)userKey[i+8] << (56 - (8*i)));
      }
    }
    
    else if (size == 24){
      k3 = (unsigned long long int)1<<63;
      
      for (int i = 0; i<8; i++){
	k2 ^= ((long long int)userKey[i] << (56 - (8*i)));
	k1 ^= ((long long int)userKey[i+8] << (56 - (8*i)));
	k0 ^= ((long long int)userKey[i+16] << (56 - (8*i)));
      }
    }
    
    else if(size == 32){
      for (int i = 0; i<8; i++){
	k3 ^= ((long long int)userKey[i] << (56-(8*i)));
	k2 ^= ((long long int)userKey[i+8] << (56-(8*i)));
	k1 ^= ((long long int)userKey[i+16] << (56-(8*i)));
	k0 ^= ((long long int)userKey[i+24] << (56-(8*i)));
      }
    }
    else{
      cout << "Key has not been set." << endl;
      cout << "SERPENT takes a 128, 192, or 256-bit key." << endl;
    }

    words[0] = (k3 >> 32);
    words[1] = (k3 & (unsigned long int)4294967295);
    words[2] = (k2 >> 32);
    words[3] = (k2 & (unsigned long int)4294957295);
    words[4] = (k1 >> 32);
    words[5] = (k1 & (unsigned long int)4294957295);
    words[6] = (k0 >> 32);
    words[7] = (k0 & (unsigned long int)4294957295);
  
 }
  
  
  /**
   * Generates the 33 128-subkeys to be used for encryption
   */
  void generateSubKeys(){
    
    for (int i = 8; i < 139; i++){
       
       words[i] = (words[i-8] ^ words[i-5] ^ words[i-3] ^ words[i-1]
		   ^ (i-8) ^ phi);
       //cout << bitset<64>(words[i]) << endl;
       words[i] = (((words[i] << 11)&((unsigned long int)4294965248))
		   ^ (words[i] >> 21));
       //cout << bitset<64>(words[i]) << endl;
     }

    

  }  

  /**
   * Sets the size to keyLength
   */

  void setKeySize( int keyLength){
    size = keyLength;
  }



  /**
   * Returns this block cipher's key size in bytes.
   *
   * @return  Key size.
   */
  int keySize (){
      
    if (size == -1){
      cout << "Keysize has not been set; returning 0." << endl;
      return 0;

    }else{
      return size;
    }
  }
};

int main(){

  unsigned char testKey[] = {0x0, 0x01, 0x01, 0x00, 
			     0x01, 0x00, 0x00, 0x01, 
			     0x01, 0x01, 0x00, 0x00, 
			     0x10, 0x10, 0x10, 0x10,
			     0x10, 0x10, 0x10, 0x10, 
			     0x01, 0x01, 0x01, 0x01, 
			     0x01, 0x01, 0x01, 0x01, 
			     0x10, 0x10, 0x10, 0x10};
  
    
  KeySchedule *ks = new KeySchedule();
  ks->setKeySize(sizeof(testKey)/sizeof(*testKey));
  ks->setKey(testKey);
  ks->generateSubKeys();
    
  return 0;
};

   

  
