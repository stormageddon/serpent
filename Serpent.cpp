#include <algorithm>
#include <cstdio>
#include <iostream>
#include <bitset>
#include <map>


class Serpent
{
  
  
private:
  
  int ip[128];
  int size;
  unsigned long long int k0;
  unsigned long long int k1;
  unsigned long long int k2;
  unsigned long long int k3;
  unsigned long int words[140];
  std::string subKeys[33];
  static const long int phi = 2654435769;
  
  int sBoxDecimalTable[8][16];
  
  
  std::map<std::string, std::string> sBoxBitstring[8];
  std::map<std::string, std::string> sBoxBitstringInverse[8];
  
public:                    // begin public section
  
  Serpent();
  
  void linearTransform(std::bitset<32> x0, std::bitset<32> x1, std::bitset<32> x2, std::bitset<32> x3);
  
  void shiftRight(unsigned char *ar, int size, int shift);
  
  void shiftLeft(unsigned char *array);

  void rotate(std::bitset<32> &b, unsigned m);

  void setKey (unsigned char userKey[]);

  void generateSubKeys();

  void setKeySize( int keyLength);

  int keySize();

  int blockSize();

  std::string Bitstring(int num, int length);

  void Setup();

  std::string S(int box, std::string input);

  std::string SInverse(int box, std::string output);

  std::string SHat(int box, std::string input);

  std::string SHatInverse(int box, std::string output);

  std::string * SBitslice(int box, std::string words[4][32]);

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
    }
}

void Serpent::linearTransform(std::bitset<32> x0, std::bitset<32> x1, std::bitset<32> x2, std::bitset<32> x3) {
  std::cout << x0 << std::endl;
  //std::cout << x1 << std::endl;
  //std::cout << x2 << std::endl;
  //std::cout << x3 << std::endl;
  rotate(x0,13);
  std::cout << x0 << std::endl;
 
  rotate(x2,3);
  x1 = x1^x0^x2;
  x0 <<= 3;
  x3 = x3^x2^x0;
  rotate(x1,1);
  rotate(x3,7);
  x0 = x0^x1^x3;
  x1 <<= 7;
  x2 = x2^x3^x1;
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
    
  if (size == -1){
    std::cout << "Keysize has not been set."<< std::endl;
    std::cout << "Call setKeySize(int n) with n = 128, 192, 256"<< std::endl;
    std::cout << "Key has not been set." << std::endl;
  }

  if (size == 16){
    k3 = (unsigned long long int)1<< 63;
            
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
    std::cout << "Key has not been set." << std::endl;
    std::cout << "SERPENT takes a 128, 192, or 256-bit key." << std::endl;
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
void Serpent::generateSubKeys(){
    
  for (int i = 8; i < 139; i++){
       
    words[i] = (words[i-8] ^ words[i-5] ^ words[i-3] ^ words[i-1]
		^ (i-8) ^ phi);
    //std::cout << bitset<64>(words[i]) << std::endl;
    words[i] = (((words[i] << 11)&((unsigned long int)4294965248))
		^ (words[i] >> 21));
    //std::cout << bitset<64>(words[i]) << std::endl;
  }
        
  std::string t;
    
  for ( int i = 0; i<33; i++ ){
      
    t = Bitstring( words[4*i + 8], 32 );
    t.append( Bitstring( words[4*i+ 9], 32 ) );
    t.append( Bitstring( words[4*i+ 10], 32 ) );
    t.append( Bitstring( words[4*i+ 11], 32 ) );
     
    /* std::cout << std::bitset<32>(words[i]) << std::endl;
       std::cout << std::bitset<32>(words[i+1]) << std::endl;
       std::cout << std::bitset<32>(words[i+2]) << std::endl;
       std::cout << std::bitset<32>(words[i+3]) << std::endl;

       std::cout << "tstring" << std::endl;
       std::cout << t << std::endl; */

    for (int j = 0; j<128; j+= 4){
      subKeys[i].append( S( (i+3), t.substr(j,4)));
      //std::cout << "j = " << j << " : " << subKeys[i] << std::endl; 
    } 
      
    t = subKeys[i];

    for (int j = 0; j<128; j++){
      subKeys[i][j] = t[ip[j]];
    }

    //    std::cout << "Subkey " << i << ": " << subKeys[i] << std::endl;
  }
   
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
  
  
std::string Serpent::Bitstring(int num, int length) {
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
  
std::string * Serpent::SBitslice(int box, std::string words[4][32]){
  static std::string bitSliceResult[] = {"", "", "", ""};
  std::string input = "";
  std::string quad;
  for (int i = 0; i < 32; i++) {
    input.append(words[0][i]);
    input.append(words[1][i]);
    input.append(words[2][i]);
    input.append(words[3][i]);
      
    quad = S(box, input);
      
    for (int j = 0; j < 4; j++) {
      bitSliceResult[j] += quad[j];
    }
  }
    
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



void Serpent::encrypt( unsigned char text[]){

  //insert bit-shifting here
  unsigned char t[129] = {};
  
  for (int j = 0; j<128; j++){
    t[j] = text[ip[j]];
    std::cout << "text at ip[j] " << text[ip[j]] << std::endl;
    std::cout << "t[j] = " << t[j] << std::endl;
    std::cout << "ip[j] = " << ip[j] << std::endl;
  }
    


  t[128] = '\0';

  std::string str ( reinterpret_cast<char*>(t),129);

  std::cout << "Here's a string " <<str << std::endl;

  //  for( int i = 0; i< 31; i++ ){
    

  
}

//}
int main(int argc, char** argv)
{
  int n;
  if (argc > 1) {
    n = std::stof(argv[1]);
  } else {
    std::cerr << "Not enough arguments\n";
    //return 1;
  }

  char buff[100];
//  sprintf(buff,"The program was run with the following command: %d",n);
 // std::cout << buff << std::endl;

  

  Serpent serpent; 
  std::bitset<32> x0 (std::string("11000000000000000000000000000110"));
  std::bitset<32> x1 (std::string("11000000000000000000000000000110"));
  std::bitset<32> x2 (std::string("11000000000000000000000000000110"));
  std::bitset<32> x3 (std::string("11000000000000000000000000000110"));
  //  serpent.linearTransform(x0,x1,x2,x3);

 unsigned char testKey[] = {0x0, 0x01, 0x01, 0x00, 
			     0x01, 0x00, 0x00, 0x01, 
			     0x01, 0x01, 0x00, 0x00, 
			     0x10, 0x10, 0x10, 0x10,
			     0x10, 0x10, 0x10, 0x10, 
			     0x01, 0x01, 0x01, 0x01, 
			     0x01, 0x01, 0x01, 0x01, 
			     0x10, 0x10, 0x10, 0x10};
  
 unsigned char plaintext[16] = 
	{0x00, 0x00,0x00,0x00,
   0x00,0x00,0x00,0x00,
   0x00,0x00,0x00,0x00,
   0x00,0x00,0x00,0x00};
 

  
 

  serpent.setKeySize(sizeof(testKey)/sizeof(*testKey));
  serpent.setKey(testKey);
  serpent.generateSubKeys();
  serpent.encrypt(plaintext);
  std::cout << "Here's some plaintext " << plaintext[3] << std::endl;
  std::cout << "Here's some testKey " << testKey[3] << std::endl;
  std::cin.get();
  return 0;
}



