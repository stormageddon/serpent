#include <algorithm>
#include <cstdio>
#include <iostream>
#include <bitset>
#include <map>
#include <string>
#include <cstring>

class Serpent
{
  
  
private:
  
  int ip[128];
  int fp[128];
  int size;
  unsigned long long int k0;
  unsigned long long int k1;
  unsigned long long int k2;
  unsigned long long int k3;
  unsigned int words[140];
  std::string subKeys[33];
  std::string bitSliceResult[4];
  static const long int phi = 2654435769;
  
  int sBoxDecimalTable[8][16];
  
  
  std::map<std::string, std::string> sBoxBitstring[8];
  std::map<std::string, std::string> sBoxBitstringInverse[8];
  
public:                    // begin public section
  
  Serpent();
  
  void linearTransform(std::bitset<32> &x0, std::bitset<32> &x1, std::bitset<32> &x2, std::bitset<32> &x3);
  
  void shiftRight(unsigned char *ar, int size, int shift);
  
  void shiftLeft(unsigned char *array);

  void rotate(std::bitset<32> &b, unsigned m);

  void setKey (unsigned char userKey[]);

  void generateSubKeys();

  void setKeySize( int keyLength);

  int keySize();

  int blockSize();

  std::string Bitstring(unsigned int num, int length);

  void Setup();

  std::string S(int box, std::string input);

  std::string SInverse(int box, std::string output);

  std::string SHat(int box, std::string input);

  std::string SHatInverse(int box, std::string output);

  std::string * SBitslice(int box, std::string words[4]);

  std::string * SBitsliceInverse(int box, std::string words[][32]);

  void encrypt( unsigned char text[]);
  
};

//class Serpent {

Serpent::Serpent() { 
  //The initial permutation. To be applied to the plaintext and keys.
  int tip[128] = 
    {0, 32, 64, 96, 1, 33, 65, 97, 2, 34, 66, 98, 3, 35, 67, 99,
     4, 36, 68, 100, 5, 37, 69, 101, 6, 38, 70, 102, 7, 39, 71, 103,
     8, 40, 72, 104, 9, 41, 73, 105, 10, 42, 74, 106, 11, 43, 75, 107,
     12, 44, 76, 108, 13, 45, 77, 109, 14, 46, 78, 110, 15, 47, 79, 111,
     16, 48, 80, 112, 17, 49, 81, 113, 18, 50, 82, 114, 19, 51, 83, 115,
     20, 52, 84, 116, 21, 53, 85, 117, 22, 54, 86, 118, 23, 55, 87, 119,
     24, 56, 88, 120, 25, 57, 89, 121, 26, 58, 90, 122, 27, 59, 91, 123,
     28, 60, 92, 124, 29, 61, 93, 125, 30, 62, 94, 126, 31, 63, 95, 127};
  
  std::copy(tip, tip+128, ip);  
  /*for( int i = 0; i < 128; i++ ) {
    ip[i] = (32 * i) % 128;
    }*/

   int tfp[128] = 
     {0, 4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 56, 60,
      64, 68, 72, 76, 80, 84, 88, 92, 96, 100, 103, 108, 112, 116, 120, 124,
      1, 5, 9, 13, 17, 21, 25, 29, 33, 37, 41, 45, 49, 53, 57, 61, 
      65, 69, 73, 77, 81, 85, 89, 93, 97, 101, 105, 109, 113, 117, 121, 125,
      2, 6, 10, 14, 18, 22, 26, 30, 34, 38, 42, 46, 50, 54, 58, 62, 
      66, 70, 74, 78, 82, 86, 90, 94, 98, 102, 106, 110, 114, 118, 122, 126,
      3, 7, 11, 15, 19, 23, 27, 31, 35, 39, 43, 47, 51, 55, 59, 63,
      67, 71, 75, 79, 83, 87, 91, 95, 99, 103, 107, 111, 115, 119, 123, 127};

  
  std::copy(tfp, tfp+128, fp);  
  
  k3 = 0; 
  k2 = 0; 
  k1 = 0;
  k0 = 0;  
  
  size = -1;
  
  int t[8][16] = {
    { 3, 8,15, 1,10, 6, 5,11,14,13, 4, 2, 7, 0, 9,12},
    {15,12, 2, 7, 9, 0, 5,10, 1,11,14, 8, 6,13, 3, 4},
    { 8, 6, 7, 9, 3,12,10,15,13, 1,14, 4, 0,11, 5, 2},
    { 0,15,11, 8,12, 9, 6, 3,13, 1, 2, 4,10, 7, 5,14},
    { 1,15, 8, 3,12, 0,11, 6, 2, 5, 4,10, 9,14, 7,13},
    {15, 5, 2,11, 4,10, 9,12, 0, 3,14, 8,13, 6, 7, 1},
    { 7, 2,12, 5, 8, 4, 6,11,14, 9, 1,15,13, 3,10, 0},
    { 1,13,15, 0,14, 8, 2,11, 7, 4,12,10, 9, 3, 5, 6}
  };
  
  std::copy( &t[0][0], &t[0][0] + (8 * 16), &sBoxDecimalTable[0][0] );
    
    std::map<std::string, std::string> dict;
    std::map<std::string, std::string> inverseDict;
    std::string index;
    std::string value;
    
    for(int x = 0; x < 8; x++) {
      dict.clear();
      inverseDict.clear();
      for(int y = 0; y < 16; y++) {
	index = Bitstring(y, 4);
	value = Bitstring(sBoxDecimalTable[x][y], 4);
	dict[index] = value;
	inverseDict[value] = index;
      }
      
      sBoxBitstring[x] = dict;
      sBoxBitstringInverse[x] = inverseDict;

      std::string bitSliceResult[4] = {"", "", "", ""};

    }
}

void Serpent::linearTransform(std::bitset<32> &x0, std::bitset<32> &x1, std::bitset<32> &x2, std::bitset<32> &x3) {
  //std::cout << x0 << std::endl;
  //std::cout << x1 << std::endl;
  //std::cout << x2 << std::endl;
  //std::cout << x3 << std::endl;
  
  
  rotate(x0,13);
  //std::cout << x0 << std::endl;
  
  rotate(x2,3);
  x1 = x1^x0^x2;
  //x0 <<= 3;
  x3 = x3^x2^(x0 << 3);
  //x3 = x3^x2^x0;
  rotate(x1,1);
  rotate(x3,7);
  x0 = x0^x1^x3;
  //x1 <<= 7;
  x2 = x2^x3^(x1 << 7);
  //x2 = x2^x3^x1;
  rotate(x0,5);
  rotate(x2,22);
  //std::cout << x0 << std::endl;
  //std::cout << x1 << std::endl;
  //std::cout << x2 << std::endl;
  //std::cout << x3 << std::endl;
  //b <<= 4;
  //rotate(b,4);
  //std::cout << b << std::endl;

}

// Rotates to the left
void Serpent::rotate(std::bitset<32> &b, unsigned m) {
      b = b << m | b >> (32-m);
  }

/**
 * Sets the key used to generate the values of subKeys[].
 * Byte array of size 16, 24, or 32
 */
void Serpent::setKey (unsigned char userKey[]){

  //need to set the size of userKey in advance so that the key can be 
  //initialized properly
  if (size == -1){
    std::cout << "Keysize has not been set."<< std::endl;
    std::cout << "Call setKeySize(int n) with n = 128, 192, 256"<< std::endl;
    std::cout << "Key has not been set." << std::endl;
  }
  
  //Check the size of the given userkey. If it's 16 or 24 bytes, pad the 
  //most significant bit with a 1 and pad the rest out with 0's
  //k0, k1, k2, k4 were initialized to 0 in the constructor.
  //What I think I'm doing is the following, given a 128 bit userkey:
  // 0x1111 1111 1111 1111 1111 1111 1111 1111,
  // k3 = 0000 0000 0000 0000
  // k2 = 8000 0000 0000 0000 since this would be appending 1 to the MSB end
  // k1 = AAAA AAAA AAAA AAAA 
  // k0 = AAAA AAAA AAAA AAAA since I am flipping the bits to change from
  // big to little-endian
  // there's a cout statement at the end that can of setkey that seems
  // to imply this is right, but maybe that's not what we should even be doing?
  //
  //(Idea for later optimization: Rather than masking each bit, create a 
  //lookup table for all reflected bytes and assign accordingly)
 
  if (size == 16){
    
    //k0 already equals 0;
    k1 = 1;
  

    //What I think I'm doing: first bit of userKey[i] gets put into the
    //8*i bit of k1, second bit of userKey[i] gets put into the 8*i + 1 bit of
    //k2, storing the 128 bits of userKey in the 64-bit values of k1 and k2
    //so that they're in little-endian form.
    //for ( int i = 0; i < 8; i++ ){

      /*
      k1 ^= ((long long int)(userKey[i] >> 7) << (8*i));
      k1 ^= (((long long int)(userKey[i] >> 6) & 1) << (8*i + 1));
      k1 ^= (((long long int)(userKey[i] >> 5) & 1) << (8*i + 2));
      k1 ^= (((long long int)(userKey[i] >> 4) & 1) << (8*i + 3));
      k1 ^= (((long long int)(userKey[i] >> 3) & 1) << (8*i + 4));
      k1 ^= (((long long int)(userKey[i] >> 2) & 1) << (8*i + 5));
      k1 ^= (((long long int)(userKey[i] >> 1) & 1) << (8*i + 6));
      k1 ^= (((long long int)(userKey[i] & 1) << (8*i + 7)));

      
      k0 ^= ((long long int)(userKey[i+8] >> 7) << (8*i));
      k0 ^= (((long long int)(userKey[i+8] >> 6) & 1) << (8*i + 1));
      k0 ^= (((long long int)(userKey[i+8] >> 5) & 1) << (8*i + 2));
      k0 ^= (((long long int)(userKey[i+8] >> 4) & 1) << (8*i + 3));
      k0 ^= (((long long int)(userKey[i+8] >> 3) & 1) << (8*i + 4));
      k0 ^= (((long long int)(userKey[i+8] >> 2) & 1) << (8*i + 5));
      k0 ^= (((long long int)(userKey[i+8] >> 1) & 1) << (8*i + 6));
      k0 ^= (((long long int)(userKey[i+8] & 1) << (8*i + 7)));
      */

      
    for (int i = 0; i<8; i++){
	
      k2 ^= ((long long int)userKey[i] << (56 - (8*i)));
      k3 ^= ((long long int)userKey[i+8] << (56 - (8*i)));
    }
  }
  
  else if (size == 24){
    
    
    k3 = 0x8000000000000000;
    for ( int i = 0; i < 8; i++ ){
      k2 ^= ((long long int)(userKey[i] >> 7) << (8*i));
      k2 ^= (((long long int)(userKey[i] >> 6) & 1) << (8*i + 1));
      k2 ^= (((long long int)(userKey[i] >> 5) & 1) << (8*i + 2));
      k2 ^= (((long long int)(userKey[i] >> 4) & 1) << (8*i + 3));
      k2 ^= (((long long int)(userKey[i] >> 3) & 1) << (8*i + 4));
      k2 ^= (((long long int)(userKey[i] >> 2) & 1) << (8*i + 5));
      k2 ^= (((long long int)(userKey[i] >> 1) & 1) << (8*i + 6));
      k2 ^= (((long long int)(userKey[i] & 1) << (8*i + 7)));
      
      k1 ^= ((long long int)(userKey[i+8] >> 7) << (8*i));
      k1 ^= (((long long int)(userKey[i+8] >> 6) & 1) << (8*i + 1));
      k1 ^= (((long long int)(userKey[i+8] >> 5) & 1) << (8*i + 2));
      k1 ^= (((long long int)(userKey[i+8] >> 4) & 1) << (8*i + 3));
      k1 ^= (((long long int)(userKey[i+8] >> 3) & 1) << (8*i + 4));
      k1 ^= (((long long int)(userKey[i+8] >> 2) & 1) << (8*i + 5));
      k1 ^= (((long long int)(userKey[i+8] >> 1) & 1) << (8*i + 6));
      k1 ^= (((long long int)(userKey[i+8] & 1) << (8*i + 7)));

      k0 ^= ((long long int)(userKey[i+16] >> 7) << (8*i));
      k0 ^= (((long long int)(userKey[i+16] >> 6) & 1) << (8*i + 1));
      k0 ^= (((long long int)(userKey[i+16] >> 5) & 1) << (8*i + 2));
      k0 ^= (((long long int)(userKey[i+16] >> 4) & 1) << (8*i + 3));
      k0 ^= (((long long int)(userKey[i+16] >> 3) & 1) << (8*i + 4));
      k0 ^= (((long long int)(userKey[i+16] >> 2) & 1) << (8*i + 5));
      k0 ^= (((long long int)(userKey[i+16] >> 1) & 1) << (8*i + 6));
      k0 ^= (((long long int)(userKey[i+16] & 1) << (8*i + 7)));
    }
    
    /*for (int i = 0; i<8; i++){
      k2 ^= ((long long int)userKey[i] << (56 - (8*i)));
      k1 ^= ((long long int)userKey[i+8] << (56 - (8*i)));
      k0 ^= ((long long int)userKey[i+16] << (56 - (8*i)));
    }
    }*/
  } 
  else if(size == 32){
    
    for (int i = 0; i<8; i++){

      k3 ^= ((long long int)(userKey[i] >> 7) << (8*i));
      k3 ^= ((((long long int)(userKey[i] >> 6) & 1) << (8*i + 1)));
      k3 ^= ((((long long int)(userKey[i] >> 5) & 1) << (8*i + 2)));
      k3 ^= ((((long long int)(userKey[i] >> 4) & 1) << (8*i + 3)));
      k3 ^= ((((long long int)(userKey[i] >> 3) & 1) << (8*i + 4)));
      k3 ^= ((((long long int)(userKey[i] >> 2) & 1) << (8*i + 5)));
      k3 ^= ((((long long int)(userKey[i] >> 1) & 1) << (8*i + 6)));
      k3 ^= (((long long int)(userKey[i] & 1) << (8*i + 7)));
      
      k2 ^= ((long long int)(userKey[i+8] >> 7) << (8*i));
      k2 ^= (((long long int)(userKey[i+8] >> 6) & 1) << (8*i + 1));
      k2 ^= (((long long int)(userKey[i+8] >> 5) & 1) << (8*i + 2));
      k2 ^= (((long long int)(userKey[i+8] >> 4) & 1) << (8*i + 3));
      k2 ^= (((long long int)(userKey[i+8] >> 3) & 1) << (8*i + 4));
      k2 ^= (((long long int)(userKey[i+8] >> 2) & 1) << (8*i + 5));
      k2 ^= (((long long int)(userKey[i+8] >> 1) & 1) << (8*i + 6));
      k2 ^= (((long long int)(userKey[i+8] & 1) << (8*i + 7)));

      k1 ^= ((long long int)(userKey[i+16] >> 7) << (8*i));
      k1 ^= (((long long int)(userKey[i+16] >> 6) & 1) << (8*i + 1));
      k1 ^= (((long long int)(userKey[i+16] >> 5) & 1) << (8*i + 2));
      k1 ^= (((long long int)(userKey[i+16] >> 4) & 1) << (8*i + 3));
      k1 ^= (((long long int)(userKey[i+16] >> 3) & 1) << (8*i + 4));
      k1 ^= (((long long int)(userKey[i+16] >> 2) & 1) << (8*i + 5));
      k1 ^= (((long long int)(userKey[i+16] >> 1) & 1) << (8*i + 6));
      k1 ^= (((long long int)(userKey[i+16] & 1) << (8*i + 7)));

      k0 ^= (((long long int)(userKey[i+24] >> 7) << (8*i)));
      k0 ^= (((long long int)(userKey[i+24] >> 6) & 1) << (8*i + 1));
      k0 ^= (((long long int)(userKey[i+24] >> 5) & 1) << (8*i + 2));
      k0 ^= (((long long int)(userKey[i+24] >> 4) & 1) << (8*i + 3));
      k0 ^= (((long long int)(userKey[i+24] >> 3) & 1) << (8*i + 4));
      k0 ^= (((long long int)(userKey[i+24] >> 2) & 1) << (8*i + 5));
      k0 ^= (((long long int)(userKey[i+24] >> 1) & 1) << (8*i + 6));
      k0 ^= (((long long int)(userKey[i+24] & 1) << (8*i + 7)));
    }
  }
    /*
    for (int i = 0; i<8; i++){
      k0 ^= ((long long int)userKey[i] << (56-(8*i)));
      k1 ^= ((long long int)userKey[i+8] << (56-(8*i)));
      k2 ^= ((long long int)userKey[i+16] << (56-(8*i)));
      k3 ^= ((long long int)userKey[i+24] << (56-(8*i)));
      }
      std::cout << "k0-k4 before swap" << std::endl;
      std::cout << std::bitset<64>(k0) ;
      std::cout << std::bitset<64>(k1);
      std::cout << std::bitset<64>(k2);
      std::cout << std::bitset<64>(k3);
      
      k3 = (((k3 & 0xaaaaaaaaaaaaaaaa) >> 1) | 
	    ((k3 & 0x5555555555555555) << 1));
      k3 = (((k3 & 0xcccccccccccccccc) >> 2) | 
	    ((k3 & 0x3333333333333333) << 2));
      k3 = (((k3 & 0xf0f0f0f0f0f0f0f0) >> 4) | 
	    ((k3 & 0x0f0f0f0f0f0f0f0f) << 4));
      k3 = (((k3 & 0xff00ff00ff00ff00) >> 8) | 
	    ((k3 & 0x00ff00ff00ff00ff) << 8));


      k2 = (((k2 & 0xaaaaaaaaaaaaaaaa) >> 1) | 
	    ((k2 & 0x5555555555555555) << 1));
      k2 = (((k2 & 0xcccccccccccccccc) >> 2) | 
	    ((k2 & 0x3333333333333333) << 2));
      k2 = (((k2 & 0xf0f0f0f0f0f0f0f0) >> 4) | 
	    ((k2 & 0x0f0f0f0f0f0f0f0f) << 4));
      k2 = (((k2 & 0xff00ff00ff00ff00) >> 8) | 
	    ((k2 & 0x00ff00ff00ff00ff) << 8));
      
      k1 = (((k1 & 0xaaaaaaaaaaaaaaaa) >> 1) | 
	    ((k1 & 0x5555555555555555) << 1));
      k1 = (((k1 & 0xcccccccccccccccc) >> 2) | 
	    ((k1 & 0x3333333333333333) << 2));
      k1 = (((k1 & 0xf0f0f0f0f0f0f0f0) >> 4) | 
	    ((k1 & 0x0f0f0f0f0f0f0f0f) << 4));
      k1 = (((k1 & 0xff00ff00ff00ff00) >> 8) | 
	    ((k1 & 0x00ff00ff00ff00ff) << 8));
     
      k0 = (((k0 & 0xaaaaaaaaaaaaaaaa) >> 1) | 
	    ((k0 & 0x5555555555555555) << 1));
      k0 = (((k0 & 0xcccccccccccccccc) >> 2) | 
	    ((k0 & 0x3333333333333333) << 2));
      k0 = (((k0 & 0xf0f0f0f0f0f0f0f0) >> 4) | 
	    ((k0 & 0x0f0f0f0f0f0f0f0f) << 4));
      k0 = (((k0 & 0xff00ff00ff00ff00) >> 8) | 
	    ((k0 & 0x00ff00ff00ff00ff) << 8));
      
      
    */
  
  else{
    std::cout << "Key has not been set." << std::endl;
    std::cout << "SERPENT takes a 128, 192, or 256-bit key." << std::endl;
  }
  
  std::cout << "k0 - k3 new method" << std::endl;
  std::cout << std::hex << k0 << std::endl;
  std::cout << std::hex << k1 << std::endl;
  std::cout << std::hex << k2 << std::endl;
  std::cout << std::hex << k3 << std::endl;
  

  //std::cout << std::bitset<64>(k0);
  //std::cout << std::bitset<64>(k1);
  //std::cout << std::bitset<64>(k2);
  //std::cout << std::bitset<64>(k3) << std::endl;
  
  // This is the weirdness with breaking the key, after it's been set
  // into 8 32-bit words. THIS IS A PLACE I FUCKED UP AND FORGOT TO CHANGE
  // SHIT AFTER THE BIG->LITTLE-ENDIAN TRANSITION!
  /*
  words[0] = (k3 >> 32);
  words[1] = (k3 & (unsigned long int)4294967295);
  words[2] = (k2 >> 32);
  words[3] = (k2 & (unsigned long int)4294967295);
  words[4] = (k1 >> 32);
  words[5] = (k1 & (unsigned long int)4294967295);
  words[6] = (k0 >> 32);
  words[7] = (k0 & (unsigned long int)4294967295);
  */

  //Let's try again...
  //4294967295 is the decimal representation of 32 bits of 1's
  //Using this to mask the 
  words[0] = (k3 & (unsigned long int)4294967295);
  words[1] = (k3 >> 32);
  words[2] = (k2 & (unsigned long int)4294967295);
  words[3] = (k2 >> 32);
  words[4] = (k1 & (unsigned long int)4294967295);
  words[5] = (k1 >> 32);
  words[6] = (k0 & (unsigned long int)4294967295);
  words[7] = (k0 >> 32);
  
  
  for (int i = 0; i < 8; i++ ){
    std::cout << "word[" << std::dec << i-8 << "] = " << std::hex << words[i] << std::endl;
    }
  
}

  
/**
 * Generates the 33 128-subkeys to be used for encryption
 */
void Serpent::generateSubKeys(){
    
  //Populate the array of words. The first 8 words are not used in the
  //final subkeys, they're just used as the seed for generation of 
  //the 33 subkeys that will be used in the encryption algorithm
  for (int i = 8; i < 140; i++){
       
    words[i] = (words[i-8] ^ words[i-5] ^ words[i-3] ^ words[i-1]
		^ (i-8) ^ phi);
    //std::cout << std::bitset<32>(words[i]) << std::endl;
    words[i] = ((words[i] << 11) | (words[i] >> 21));
    // std::cout << std::bitset<32>(words[i-8]) << std::endl;
    //Just put this in here to try and track values through generate subkeys
    //And didn't want to deal with everything at once
    //if (( i >135) && (i <= 139 )){
    // std::cout << "Word[" << std::dec <<i-8 << "] initialized to " << 
    // std::hex << words[i] << std::endl;
      // std::cout << std::bitset<32>(words[i]) << std::endl;
      // }
  }

  //This shit flips bits
  for (int i = 8; i<140; i++){
    
    words[i] = (((words[i] & 0xaaaaaaaa) >> 1) | 
		((words[i] & 0x55555555) << 1));
    words[i] = (((words[i] & 0xcccccccc) >> 2) | 
		((words[i] & 0x33333333) << 2));
    words[i] = (((words[i] & 0xf0f0f0f0) >> 4) | 
		((words[i] & 0x0f0f0f0f) << 4));
    words[i] = (((words[i] & 0xff00ff00) >> 8) | 
		((words[i] & 0x00ff00ff) << 8));
    words[i] = (( words[i] >> 16) | (words[i] << 16));
    //      std::cout << "words[" << std::dec <<  i-8 << "] : " 
    //	<< std::bitset<32>(words[i]) << std::endl;
  }

  // Things have tested correct up until this point
  // When comparing this section to the Python implementation, note that
  // Ki contains the subkeys before the initial permutation, but after
  // the Sbox stage. KHat contains the subkeys after the initial permutation.

  std::string preKeys[132];
  for ( int i = 0; i<33; i++ ){

    std::string sBoxInput0 = Bitstring( words[4*i + 8], 32 );
    std::string sBoxInput1 = Bitstring( words[4*i + 9], 32);
    std::string sBoxInput2 = Bitstring( words[4*i + 10], 32);
    std::string sBoxInput3 = Bitstring( words[4*i + 11], 32); 
    
    /*for ( int j = 0; j<32; j++ ){
      
      std::string sBoxInput = "";
            	
      sBoxInput += sBoxInput0[j];
      sBoxInput += sBoxInput1[j];
      sBoxInput += sBoxInput2[j];
      sBoxInput += sBoxInput3[j];
        
      std::string sBoxString = S( 35 - i, sBoxInput);
    }*/

    //subKeys[i] = "";

    for ( int k = 0; k< 33; k++ ){

      std::string input = "";
      input.append(1, sBoxInput0[k]);
      input.append(1, sBoxInput1[k]);
      input.append(1, sBoxInput2[k]);
      input.append(1, sBoxInput3[k]);
      std::cout << "Input at[ " << std::dec << i << "][" << k << "] : "
		<< input << std::endl;

      std::string result = S( 35 - i, input);
      std::cout  << "Result after sbox: " << result << std::endl;

      //std::cout << "THIS IS AN AMAZING STRING" << std::endl;
      //std::cout << result[0] << std::endl;
      //std::cout << result[0].length() << std::endl; 
      
      for ( int j = 0; j<4 ; j++ ){
	//	std::cout << "result " << 4*i + j << ": " << result[j] << std::endl; 
	preKeys[j + 4*i] = preKeys[j+ 4*i] + result[j];

      }
    }
  }
  
  for ( int i = 0; i<33; i++ ){
    
    subKeys[i].append(preKeys[4*i]);
    subKeys[i].append(preKeys[4*i + 1]);
    subKeys[i].append(preKeys[4*i + 2]);
    subKeys[i].append(preKeys[4*i + 3]);
    
  }
  std::string t = "";  
    /*
    t.append( Bitstring( words[4*i + 8], 32 ) );
    t.append( Bitstring( words[4*i+ 9], 32 ) );
    t.append( Bitstring( words[4*i+ 10], 32 ) );
    t.append( Bitstring( words[4*i+ 11], 32 ) );
    */
    //Selectively printing the string that should now contain the same words
    //printed out previously (words 136-139)
    //if(i == 32){
    //std::cout << "T at round " << i << " of keygen = " << t << std::endl;
    //}
    /* std::cout << std::bitset<32>(words[i]) << std::endl;
       std::cout << std::bitset<32>(words[i+1]) << std::endl;
       std::cout << std::bitset<32>(words[i+2]) << std::endl;
       std::cout << std::bitset<32>(words[i+3]) << std::endl;

       std::cout << "tstring" << std::endl;
       std::cout << t << std::endl; */
    //std::cout << "subKey before appending " << subKeys[i] << std::endl;
    //if( i ==32 ){
      // std::cout << "Sbox 3 applied to t " << std::endl;
    //}
    
    for (int j = 0; j<128; j+= 4){
      
      //The subkeys are passed through the sboxes, starting with sbox 3
      //and descending. There was another mistake here, where I cycled
      //through the sboxes in ascending order instead of descending
      //The sbox to be used is written as 35 - i because c++ will NOT
      //recognize -1 mod 8 as 7. I tried writing it as 3-i and found this out.
      
      /*
      if(i == 32){
	if (j % 32 == 0){
	  std::cout << std::endl;
	}
	std::cout << S( 35 - i, t.substr(j,4)) ;
	
	
      }
      */
      //subKeys[i].append( S( 35 - i, t.substr(j,4)));
      
      //std::cout <<"appended to subKey "<< i << " " << subKeys[i] << std::endl;
      //std::cout << "j = " << j << " : " << subKeys[i] << std::endl; 
    }

    for (int i = 0; i < 33; i ++ ){
      std::cout << "Subkey before IP" << std::dec << i << ": " << std::endl;
      std::cout << subKeys[i] << std::endl;
      
      t = subKeys[i];
      
      for (int j = 0; j<128; j++){
	subKeys[i][j] = t[ip[j]];
      }
      
      std::cout<< std::endl;
      std::cout << "Subkey after IP" << std::dec << i << ": " << std::endl;
      
      std::cout << subKeys[i] << std::endl;
    }
    /*
    std::cout << subKeys[i].substr(0,32) << std::endl;
    std::cout << subKeys[i].substr(32,32) << std::endl;
    std::cout << subKeys[i].substr(64,32) << std::endl;
    std::cout << subKeys[i].substr(96,32) << std::endl;
    */
    
}



/**
 * Sets the size to keyLength
 */

void Serpent::setKeySize( int keyLength){
  size = keyLength;
}



/**
 * Returns this block cipher's key size in bytes.
 *
 * @return  Key size.
 */
int Serpent::keySize (){
      
  if (size == -1){
    std::cout << "Keysize has not been set; returning 0." << std::endl;
    return 0;
      
  }else{
    return size;
  }
}
  
  
std::string Serpent::Bitstring(unsigned int num, int length) {
  std::string result = "";
  while(num > 0) {
    if (num & 1)
      result = "1" + result;
    else
      result = "0" + result;
      
    num >>= 1;
  }
    
  if (result.length() < length)
    result.insert(0,(length - result.length()), '0');
  
  return result;
}
  
std::string Serpent::S(int box, std::string input){
  return sBoxBitstring[box%8][input];
}
  
std::string Serpent::SInverse(int box, std::string output){
  return sBoxBitstringInverse[box%8][output];
}
  
std::string Serpent::SHat(int box, std::string input){
  std::string result = "";
  
  for(int i = 0; i < 32; i++) {
    result.append(S(box, input.substr((4*i), 4)));
  }
    
    
  return result;
}
  
std::string Serpent::SHatInverse(int box, std::string output){
  std::string result = "";
    
  for (int i = 0; i < 32; i++) {
    result.append(SInverse(box, output.substr((4*i), 4)));
  }
    
  return result;
}
  
std::string * Serpent::SBitslice(int box, std::string param[4]){

  for (int i = 0; i < 4; i++ ){
    bitSliceResult[i].clear();
  }

  std::string input = "";
  std::string quad;
  for (int i = 0; i < 32; i++) {
    input.append(1, param[0][i]);
    input.append(1, param[1][i]);
    input.append(1, param[2][i]);
    input.append(1, param[3][i]);
    quad = S(box, input);
    
    for (int j = 0; j < 4; j++) {
      bitSliceResult[j] += quad[j];
    }
    input = "";
  }
  
  //  std::cout << bitSliceResult[0] << std::endl;
  return bitSliceResult;
}
  
std::string * Serpent::SBitsliceInverse(int box, std::string words[][32]){
  static std::string bitSliceInverseResult[] = {"", "", "", ""};
  std::string output = "";
  std::string quad;
  for (int i = 0; i < 32; i++) {
    output.append(words[0][i]);
    output.append(words[1][i]);
    output.append(words[2][i]);
    output.append(words[3][i]);
      
    quad = SInverse(box, output);
      
    for (int j = 0; j < 4; j++) {
      bitSliceInverseResult[j] += quad[j];
    }
  }
    
  return bitSliceInverseResult;
}



void Serpent::encrypt( unsigned char text[16] ){
  
  std::string temp (128, '0');
  std::string state = "";
  
  for (int i = 0; i<16; i++){
    state.append(Bitstring((unsigned int)text[i], 8));
  }

  std::cout << "State before any changes: " << state << std::endl;
  
  for (int j = 0; j<128; j++){
    temp[j] = (state[ip[j]]);
    // std::cout << "text at ip[j] " << state[ip[j]] << std::endl;
    //std::cout << "t[" << j << "] = " << temp[j] << std::endl;
    //std::cout << "ip[j] = " << ip[j] << std::endl; 
   
  }
  std::cout << "State after initial permutation : " << temp <<std::endl;
  int round;
  for ( round = 0; round < 31; round ++ ){
    
    state = "";
    for( int index = 0; index<128; index++ ){
      
      // std::cout << "Subkey[" << round << "]["
      //	<< index << "] is " << subKeys[round][index] << std::endl;
      
      //std::cout << "temp[" << index << "] = " <<(int)temp[index] << std::endl;
      
      state.append( std::to_string((int)temp[index] ^ 
				   (int)subKeys[round][index]) ); 
      
      
      //std::cout << "temp [" << index << "] after xor = " 
      //  << (char)temp[index] << std::endl;
    }
    
    //std::cout << "temp = " << temp << "and has length = " 
    //	      << temp.length() <<std::endl;
    
    temp = SHat( round, state );

    std::bitset<32> state0 (temp.substr(0,32));
    std::bitset<32> state1 (temp.substr(32,31));
    std::bitset<32> state2 (temp.substr(64,31));
    std::bitset<32> state3 (temp.substr(96,31));

    /* 
    std::cout << "state bitsets before linearTransform: " << std::endl;
    std::cout << state0 << std::endl;
    std::cout << state1 << std::endl;
    std::cout << state2 << std::endl;
    std::cout << state3 << std::endl;
    */
    
    linearTransform( state0, state1, state2, state3 );
    
    
    state = state0.to_string
      <char, std::string::traits_type, std::string::allocator_type>();
    
    state.append(state1.to_string <char, std::string::traits_type, std::string::allocator_type>());

    state.append(state2.to_string<char, std::string::traits_type, std::string::allocator_type>());

    state.append(state3.to_string<char, std::string::traits_type, std::string::allocator_type>());
    /*
    std::cout << "state bitsets after linearTransform: " << std::endl;
    std::cout << state0 << std::endl;
    std::cout << state1 << std::endl;
    std::cout << state2 << std::endl;
    std::cout << state3 << std::endl;*/
  }
  
  // Penultimate xor with 32rd subkey
  for ( int index = 0; index<128; index++){
    
    state.append( std::to_string((int)temp[index] ^ 
				 (int)subKeys[round][index]) ); 
  }        
    temp = SHat( round, state );  
 
  // Final xor with 33rd subkey
  state = "";  
  for ( int index = 0; index<128; index++){
  
    state.append( std::to_string((int)temp[index] ^ 
				 (int)subKeys[round+1][index]) ); 
  }
 
  for (int j = 0; j<128; j++){
    temp[j] = (state[fp[j]]);
    // std::cout << "text at fp[j] " << state[fp[j]] << std::endl;
    //std::cout << "t[" << j << "] = " << temp[j] << std::endl;
    //std::cout << "fp[j] = " << fp[j] << std::endl; 
  }    
   
  std::cout << "Temp after uuuuurything: " << temp << std::endl;
}

int main(int argc, char** argv)
{
  int n;
   if (argc > 1) {
    n = std::stof(argv[1]);
  } else {
    std::cerr << "Not enough arguments\n";
    return 1;
  }

  char buff[100];
  sprintf(buff,"The program was run with the following command: %d",n);
  std::cout << buff << std::endl;

  
  Serpent serpent; 
  std::bitset<32> x0 (std::string("11000000000000000000000000000110"));
  std::bitset<32> x1 (std::string("11000000000000000000000000000110"));
  std::bitset<32> x2 (std::string("11000000000000000000000000000110"));
  std::bitset<32> x3 (std::string("11000000000000000000000000000110"));
  //  serpent.linearTransform(x0,x1,x2,x3);

 unsigned char testKey[] = {0x80, 0x00, 0x00, 0x00, 
			    0x00, 0x00, 0x00, 0x00, 
			    0x00, 0x00, 0x00, 0x00, 
			    0x00, 0x00, 0x00, 0x00};
 /*
			    0x00, 0x00, 0x00, 0x00, 
			    0x00, 0x00, 0x00, 0x00,
			    0x00, 0x00, 0x00, 0x00, 
			    0x00, 0x00, 0x00, 0x00};
 */

 unsigned char plaintext[16] = 
   {0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00};

 std::cout << "testkey after declaration: " << std::endl;

 for (int i = 0; i<16; i++ ){
   if ((i%4 == 0) && (!i==0)){
   std::cout << std::endl;
   }
   std::cout << serpent.Bitstring(int(testKey[i]), 8);
 }
 std::cout << std::endl;

 //std::cout << bitset<64>(words[i]) << std::endl;
 serpent.setKeySize(sizeof(testKey)/sizeof(*testKey));
 serpent.setKey(testKey);
 serpent.generateSubKeys();
 //serpent.encrypt(plaintext);
 //std::cout << "Here's some plaintext " 
 //  << (unsigned int)plaintext[3] << std::endl;

  return 0;
}



