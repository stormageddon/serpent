
#include <iostream>
#include <bitset>
#include <string>
#include <cstring>
#include <tuple>
#include <map>
#include <sstream>
#include <fstream>

class Serpent
{
  
  
private:

    
  int ip[128];                       //initial permutation
  int fp[128];                       //final permutation
  const char * hexTable;             //a string used for converting to hex

  //a lookup for the binary representation of an int 0<=i<=15
  std::string dec2bin[16];           
  int size;                          //size of the key


 //a lookup table for ints from binary strings
  std::map<std::string, int> bin2dec;   

  //k0-k3 are the 64-bit pieces of the 256-bit key used for encryption
  unsigned long long int k0;               
  unsigned long long int k1;
  unsigned long long int k2;
  unsigned long long int k3;

  //words holds the 32-bit words used to generate the 33 keys used 
  //for encryption
  //N.B. words 0-7 are used as a seed to generate the remaining 132 
  //words, but are not themselves used in the keys.
  std::bitset<32> words[140];
  
  //subKeys holds the 33 128-bit keys used for encryption
  std::tuple< std::bitset<64>, std::bitset<64> > subKeys[33];

  //phi is a constant used in the word-generating affine recurrence
  static const unsigned long int phi = 2654435769;
  
   //The 8 sboxes used for encryption
  int sBoxes[8][16];

  //The 8 inverse sboxes used for decryption
  int inverseSBoxes[8][16];

  //transform positions indicates what values should be xored together
  //during the linear transformation. 
  //to determine the 0th bit of output, xor the values listed in 
  //transformPositions[0] and so forth.
  int transformPositions[128][7];
 
 
  //the inverse of transformPositions. used for decryption
  int inverseTransformPositions[128][7];
    
public:                    // begin public section
  
  Serpent();

   //The regular linear transformation that takes place in rounds 0-30
  std::tuple< std::bitset<64>, std::bitset<64> >
  linearTransform(std::tuple< std::bitset<64>, std::bitset<64> > state);

  //The inverse of the linear transformation. Used for decryption
  std::tuple< std::bitset<64>, std::bitset<64> >
  inverseLinearTransform(std::tuple< std::bitset<64>, std::bitset<64> > state);

  //Rotate "left" according to the Serpent specification. In fact this 
  //rotates right in big-endian notation, but all internal computation is 
  //in the Serpent algorithm is little-endian
  void rotate(std::bitset<32> &b, unsigned m);

  //Sets the key to be used for encryption or decryption.
  //N.B. key size must have already been set with setKeySize()
  //for this to work properly
  void setKey (unsigned char userKey[]);


  //Populates the subKeys array with the subkeys to be used during encryption
  void generateSubKeys();

  //Sets the key size for encryption in bytes. Serpent supports
  //16, 24, and 32 byte keys
  void setKeySize( int keyLength);

  //Returns the size of the user-supplied key.
  int keySize();

  //Returns the plaintext block size in bytes. Serpent only supports
  //a 16 byte blocksize
  int blockSize();

  //Passes the state through the given sbox, four bits at a time
  std::tuple< std::bitset<64>, std::bitset<64> > 
  SBitset( int box,  std::tuple< std::bitset<64>, std::bitset<64> > state );

  //Passes the state through the given inverse sbox, four bits at a time
  std::tuple < std::bitset<64>, std::bitset<64> >
  inverseSBitset( int box, std::tuple< std::bitset<64>, std::bitset<64> > 
		  state);

  //Returns a mirror image of the given binary string
  std::string bitMirrorString (std::string image, std::string reflection);

  //Returns a mirror image of the given int
  //NB the mirror image is reflected about the 16th bit
  unsigned int bitMirrorInt ( unsigned int image );

  //Returns a mirror image of the given byte
  unsigned char bitMirrorByte( unsigned char image);

  //Returns a mirror image of the given 32-bit bitset
  std::bitset<32> bitMirrorBitset ( std::bitset<32> image );

  //Returns a mirror image of the state
  std::tuple< std::bitset<64>, std::bitset<64> > 
  bitMirrorTuple ( std::tuple< std::bitset<64>, std::bitset<64> > image );


  //Returns the integer value of 4 bits from the given bitset of length 64
  //starting from pos
  unsigned int fourBits64 (std::bitset<64> halfstate, int pos);


  //Returns the integer value of 4 bits of state, with pos indicating bit 0
  unsigned int fourBits 
  ( std::tuple< std::bitset<64>, std::bitset<64> > state, int pos );


  //Returns the integer value of 4 bits of state, with 1 bit taken from
  //each of the four words, starting as pos
  unsigned int fourBitsFromWords ( std::bitset<32> word0, 
				   std::bitset<32> word1, 
				   std::bitset<32> word2, 
				   std::bitset<32> word3,
				   int pos);
  
  //Returns a hexadecimal representation of the state
  std::string hexString (std::tuple< std::bitset<64>, std::bitset<64> > state);

  //Take the string in Serpent format and return a string in NESSIE format
  std::string nessify (std::string reformat);

  //Prints the state in big-endian hexadecimal
  void printState (std::tuple< std::bitset<64>, std::bitset<64> > string);

  //Reads 8 bytes into an unsigned long long int.
  //Used for reading in the unsigned char[] input
  unsigned long long int readIn ( unsigned char bytes[8] );

  //Applies the initial permutation to the state
  std::tuple< std::bitset<64>, std::bitset<64> > 
  initialP ( std::tuple< std::bitset<64>, std::bitset<64> > state );
    
  //Applies the final permutation to the state
  std::tuple< std::bitset<64>, std::bitset<64> > 
  finalP ( std::tuple< std::bitset<64>, std::bitset<64> > state );
  
   //Encrypt the given plaintext
  void encrypt( unsigned char * text );

  //Decrypt the given ciphertext
  void decrypt ( unsigned char * text );
  
};


//class Serpent {

Serpent::Serpent() { 
  
  //The initial permutation. To be applied to the plaintext and keys.
   int tempIP[128] = 
    {0, 32, 64, 96, 1, 33, 65, 97, 2, 34, 66, 98, 3, 35, 67, 99,
     4, 36, 68, 100, 5, 37, 69, 101, 6, 38, 70, 102, 7, 39, 71, 103,
     8, 40, 72, 104, 9, 41, 73, 105, 10, 42, 74, 106, 11, 43, 75, 107,
     12, 44, 76, 108, 13, 45, 77, 109, 14, 46, 78, 110, 15, 47, 79, 111,
     16, 48, 80, 112, 17, 49, 81, 113, 18, 50, 82, 114, 19, 51, 83, 115,
     20, 52, 84, 116, 21, 53, 85, 117, 22, 54, 86, 118, 23, 55, 87, 119,
     24, 56, 88, 120, 25, 57, 89, 121, 26, 58, 90, 122, 27, 59, 91, 123,
     28, 60, 92, 124, 29, 61, 93, 125, 30, 62, 94, 126, 31, 63, 95, 127};
  
  std::copy(tempIP, tempIP+128, ip);  

  //The final permutation
   int tempFP[128] = 
     {0, 4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 56, 60,
      64, 68, 72, 76, 80, 84, 88, 92, 96, 100, 104, 108, 112, 116, 120, 124,
      1, 5, 9, 13, 17, 21, 25, 29, 33, 37, 41, 45, 49, 53, 57, 61, 
      65, 69, 73, 77, 81, 85, 89, 93, 97, 101, 105, 109, 113, 117, 121, 125,
      2, 6, 10, 14, 18, 22, 26, 30, 34, 38, 42, 46, 50, 54, 58, 62, 
      66, 70, 74, 78, 82, 86, 90, 94, 98, 102, 106, 110, 114, 118, 122, 126,
      3, 7, 11, 15, 19, 23, 27, 31, 35, 39, 43, 47, 51, 55, 59, 63,
      67, 71, 75, 79, 83, 87, 91, 95, 99, 103, 107, 111, 115, 119, 123, 127};

  
  std::copy(tempFP, tempFP+128, fp);  

  //Linear transform indices. For example, output bit 0 would come from the 
  //xor of bits 16, 52, 56, 70, 83, 94, and 105
  int ttransformPositions[128][7] = 
    {
      {16, 52, 56, 70, 83, 94, 105}, {72, 114, 125, 128, 128, 128, 128},
      {2, 9, 15, 30, 76, 84, 126}, {36, 90, 103, 128, 128, 128, 128},
      {20, 56, 60, 74, 87, 98, 109}, {1, 76, 118, 128, 128, 128, 128},
      {2, 6, 13, 19, 34, 80, 88}, {40, 94, 107, 128, 128, 128, 128},
      {24, 60, 64, 78, 91, 102, 113}, {5, 80, 122, 128, 128, 128, 128},
      {6, 10, 17, 23, 38, 84, 92}, {44, 98, 111, 128, 128, 128, 128},
      {28, 64, 68, 82, 95, 106, 117}, {9, 84, 126, 128, 128, 128, 128},
      {10, 14, 21, 27, 42, 88, 96}, {48, 102, 115, 128, 128, 128, 128},
      {32, 68, 72, 86, 99, 110, 121}, {2, 13, 88, 128, 128, 128, 128},
      {14, 18, 25, 31, 46, 92, 100}, {52, 106, 119, 128, 128, 128, 128},
      {36, 72, 76, 90, 103, 114, 125}, {6, 17, 92, 128, 128, 128, 128},
      {18, 22, 29, 35, 50, 96, 104}, {56, 110, 123, 128, 128, 128, 128},
      {1, 40, 76, 80, 94, 107, 118}, {10, 21, 96, 128, 128, 128, 128},
      {22, 26, 33, 39, 54, 100, 108}, {60, 114, 127, 128, 128, 128, 128},
      {5, 44, 80, 84, 98, 111, 122}, {14, 25, 100, 128, 128, 128, 128},
      {26, 30, 37, 43, 58, 104, 112}, {3, 118, 128, 128, 128, 128, 128},
      {9, 48, 84, 88, 102, 115, 126}, {18, 29, 104, 128, 128, 128, 128},
      {30, 34, 41, 47, 62, 108, 116}, {7, 122, 128, 128, 128, 128, 128},
      {2, 13, 52, 88, 92, 106, 119}, {22, 33, 108, 128, 128, 128, 128},
      {34, 38, 45, 51, 66, 112, 120}, {11, 126, 128, 128, 128, 128, 128},
      {6, 17, 56, 92, 96, 110, 123}, {26, 37, 112, 128, 128, 128, 128},
      {38, 42, 49, 55, 70, 116, 124}, {2, 15, 76, 128, 128, 128, 128},
      {10, 21, 60, 96, 100, 114, 127}, {30, 41, 116, 128, 128, 128, 128},
      {0, 42, 46, 53, 59, 74, 120}, {6, 19, 80, 128, 128, 128, 128},
      {3, 14, 25, 100, 104, 118, 128}, {34, 45, 120, 128, 128, 128, 128},
      {4, 46, 50, 57, 63, 78, 124}, {10, 23, 84, 128, 128, 128, 128},
      {7, 18, 29, 104, 108, 122, 128}, {38, 49, 124, 128, 128, 128, 128},
      {0, 8, 50, 54, 61, 67, 82}, {14, 27, 88, 128, 128, 128, 128},
      {11, 22, 33, 108, 112, 126, 128}, {0, 42, 53, 128, 128, 128, 128},
      {4, 12, 54, 58, 65, 71, 86}, {18, 31, 92, 128, 128, 128, 128},
      {2, 15, 26, 37, 76, 112, 116}, {4, 46, 57, 128, 128, 128, 128},
      {8, 16, 58, 62, 69, 75, 90}, {22, 35, 96, 128, 128, 128, 128},
      {6, 19, 30, 41, 80, 116, 120}, {8, 50, 61, 128, 128, 128, 128},
      {12, 20, 62, 66, 73, 79, 94}, {26, 39, 100, 128, 128, 128, 128},
      {10, 23, 34, 45, 84, 120, 124}, {12, 54, 65, 128, 128, 128, 128},
      {16, 24, 66, 70, 77, 83, 98}, {30, 43, 104, 128, 128, 128, 128},
      {0, 14, 27, 38, 49, 88, 124}, {16, 58, 69, 128, 128, 128, 128},
      {20, 28, 70, 74, 81, 87, 102}, {34, 47, 108, 128, 128, 128, 128},
      {0, 4, 18, 31, 42, 53, 92}, {20, 62, 73, 128, 128, 128, 128},
      {24, 32, 74, 78, 85, 91, 106}, {38, 51, 112, 128, 128, 128, 128},
      {4, 8, 22, 35, 46, 57, 96}, {24, 66, 77, 128, 128, 128, 128},
      {28, 36, 78, 82, 89, 95, 110}, {42, 55, 116, 128, 128, 128, 128},
      {8, 12, 26, 39, 50, 61, 100}, {28, 70, 81, 128, 128, 128, 128},
      {32, 40, 82, 86, 93, 99, 114}, {46, 59, 120, 128, 128, 128, 128},
      {12, 16, 30, 43, 54, 65, 104}, {32, 74, 85, 128, 128, 128, 128},
      {36, 90, 103, 118, 128, 128, 128}, {50, 63, 124, 128, 128, 128, 128},
      {16, 20, 34, 47, 58, 69, 108}, {36, 78, 89, 128, 128, 128, 128},
      {40, 94, 107, 122, 128, 128, 128}, {0, 54, 67, 128, 128, 128, 128},
      {20, 24, 38, 51, 62, 73, 112}, {40, 82, 93, 128, 128, 128, 128},
      {44, 98, 111, 126, 128, 128, 128}, {4, 58, 71, 128, 128, 128, 128},
      {24, 28, 42, 55, 66, 77, 116}, {44, 86, 97, 128, 128, 128, 128},
      {2, 48, 102, 115, 128, 128, 128}, {8, 62, 75, 128, 128, 128, 128},
      {28, 32, 46, 59, 70, 81, 120}, {48, 90, 101, 128, 128, 128, 128},
      {6, 52, 106, 119, 128, 128, 128}, {12, 66, 79, 128, 128, 128, 128},
      {32, 36, 50, 63, 74, 85, 124}, {52, 94, 105, 128, 128, 128, 128},
      {10, 56, 110, 123, 128, 128, 128}, {16, 70, 83, 128, 128, 128, 128},
      {0, 36, 40, 54, 67, 78, 89}, {56, 98, 109, 128, 128, 128, 128},
      {14, 60, 114, 127, 128, 128, 128}, {20, 74, 87, 128, 128, 128, 128},
      {4, 40, 44, 58, 71, 82, 93}, {60, 102, 113, 128, 128, 128, 128},
      {3, 18, 72, 114, 118, 125, 128}, {24, 78, 91, 128, 128, 128, 128},
      {8, 44, 48, 62, 75, 86, 97}, {64, 106, 117, 128, 128, 128, 128},
      {1, 7, 22, 76, 118, 122, 128}, {28, 82, 95, 128, 128, 128, 128},
      {12, 48, 52, 66, 79, 90, 101}, {68, 110, 121, 128, 128, 128, 128},
      {5, 11, 26, 80, 122, 126, 128}, {32, 86, 99, 128, 128, 128, 128},
    };
  
  std::copy( &ttransformPositions[0][0], &ttransformPositions[0][0]+128*7, 
	     &transformPositions[0][0] );
 
  //The inverse linear transformation lookup
  int tinverseTransformPositions[128][7]  = 
    {
      {53, 55, 72, -1, -1, -1, -1}, {1, 5, 20, 90, -1, -1, -1},
      {15, 102, -1, -1, -1, -1, -1}, {3, 31, 90, -1, -1, -1, -1},
      {57, 59, 76, -1, -1, -1, -1}, {5, 9, 24, 94, -1, -1, -1},
      {19, 106, -1, -1, -1, -1, -1}, {7, 35, 94, -1, -1, -1, -1},
      {61, 63, 80, -1, -1, -1, -1}, {9, 13, 28, 98, -1, -1, -1},
      {23, 110, -1, -1, -1, -1, -1},  {11, 39, 98, -1, -1, -1, -1},
      {65, 67, 84, -1, -1, -1, -1},  {13, 17, 32, 102, -1, -1, -1},
      {27, 114, -1, -1, -1, -1, -1},  {1, 3, 15, 20, 43, 102, -1},
      {69, 71, 88, -1, -1, -1, -1},  {17, 21, 36, 106, -1, -1, -1},
      {1, 31, 118, -1, -1, -1, -1},  {5, 7, 19, 24, 47, 106, -1},
      {73, 75, 92, -1, -1, -1, -1},  {21, 25, 40, 110, -1, -1, -1},
      {5, 35, 122, -1, -1, -1, -1},  {9, 11, 23, 28, 51, 110, -1},
      {77, 79, 96, -1, -1, -1, -1},  {25, 29, 44, 114, -1, -1, -1},
      {9, 39, 126, -1, -1, -1, -1},  {13, 15, 27, 32, 55, 114, -1},
      {81, 83, 100, -1, -1, -1, -1},  {1, 29, 33, 48, 118, -1, -1},
      {2, 13, 43, -1, -1, -1, -1},  {1, 17, 19, 31, 36, 59, 118},
      {85, 87, 104, -1, -1, -1, -1},  {5, 33, 37, 52, 122, -1, -1},
      {6, 17, 47, -1, -1, -1, -1},  {5, 21, 23, 35, 40, 63, 122},
      {89, 91, 108, -1, -1, -1, -1},  {9, 37, 41, 56, 126, -1, -1},
      {10, 21, 51, -1, -1, -1, -1},  {9, 25, 27, 39, 44, 67, 126},
      {93, 95, 112, -1, -1, -1, -1},  {2, 13, 41, 45, 60, -1, -1},
      {14, 25, 55, -1, -1, -1, -1},  {2, 13, 29, 31, 43, 48, 71},
      {97, 99, 116, -1, -1, -1, -1},  {6, 17, 45, 49, 64, -1, -1},
      {18, 29, 59, -1, -1, -1, -1},  {6, 17, 33, 35, 47, 52, 75},
      {101, 103, 120, -1, -1, -1, -1},  {10, 21, 49, 53, 68, -1, -1},
      {22, 33, 63, -1, -1, -1, -1},  {10, 21, 37, 39, 51, 56, 79},
      {105, 107, 124, -1, -1, -1, -1},  {14, 25, 53, 57, 72, -1, -1},
      {26, 37, 67, -1, -1, -1, -1},  {14, 25, 41, 43, 55, 60, 83},
      {0, 109, 111, -1, -1, -1, -1},  {18, 29, 57, 61, 76, -1, -1},
      {30, 41, 71, -1, -1, -1, -1},  {18, 29, 45, 47, 59, 64, 87},
      {4, 113, 115, -1, -1, -1, -1},  {22, 33, 61, 65, 80, -1, -1},
      {34, 45, 75, -1, -1, -1, -1},  {22, 33, 49, 51, 63, 68, 91},
      {8, 117, 119, -1, -1, -1, -1},  {26, 37, 65, 69, 84, -1, -1},
      {38, 49, 79, -1, -1, -1, -1},  {26, 37, 53, 55, 67, 72, 95},
      {12, 121, 123, -1, -1, -1, -1},  {30, 41, 69, 73, 88, -1, -1},
      {42, 53, 83, -1, -1, -1, -1},  {30, 41, 57, 59, 71, 76, 99},
      {16, 125, 127, -1, -1, -1, -1},  {34, 45, 73, 77, 92, -1, -1},
      {46, 57, 87, -1, -1, -1, -1},  {34, 45, 61, 63, 75, 80, 103},
      {1, 3, 20, -1, -1, -1, -1},  {38, 49, 77, 81, 96, -1, -1},
      {50, 61, 91, -1, -1, -1, -1},  {38, 49, 65, 67, 79, 84, 107},
      {5, 7, 24, -1, -1, -1, -1},  {42, 53, 81, 85, 100, -1, -1},
      {54, 65, 95, -1, -1, -1, -1},  {42, 53, 69, 71, 83, 88, 111},
      {9, 11, 28, -1, -1, -1, -1},  {46, 57, 85, 89, 104, -1, -1},
      {58, 69, 99, -1, -1, -1, -1},  {46, 57, 73, 75, 87, 92, 115},
      {13, 15, 32, -1, -1, -1, -1},  {50, 61, 89, 93, 108, -1, -1},
      {62, 73, 103, -1, -1, -1, -1},  {50, 61, 77, 79, 91, 96, 119},
      {17, 19, 36, -1, -1, -1, -1},  {54, 65, 93, 97, 112, -1, -1},
      {66, 77, 107, -1, -1, -1, -1},  {54, 65, 81, 83, 95, 100, 123},
      {21, 23, 40, -1, -1, -1, -1},  {58, 69, 97, 101, 116, -1, -1},
      {70, 81, 111, -1, -1, -1, -1},  {58, 69, 85, 87, 99, 104, 127},
      {25, 27, 44, -1, -1, -1, -1},  {62, 73, 101, 105, 120, -1, -1},
      {74, 85, 115, -1, -1, -1, -1},  {3, 62, 73, 89, 91, 103, 108},
      {29, 31, 48, -1, -1, -1, -1},  {66, 77, 105, 109, 124, -1, -1},
      {78, 89, 119, -1, -1, -1, -1},  {7, 66, 77, 93, 95, 107, 112},
      {33, 35, 52, -1, -1, -1, -1},  {0, 70, 81, 109, 113, -1, -1},
      {82, 93, 123, -1, -1, -1, -1},  {11, 70, 81, 97, 99, 111, 116},
      {37, 39, 56, -1, -1, -1, -1},  {4, 74, 85, 113, 117, -1, -1},
      {86, 97, 127, -1, -1, -1, -1},  {15, 74, 85, 101, 103, 115, 120},
      {41, 43, 60, -1, -1, -1, -1},  {8, 78, 89, 117, 121, -1, -1},
      {3, 90, -1, -1, -1, -1, -1},  {19, 78, 89, 105, 107, 119, 124},
      {45, 47, 64, -1, -1, -1, -1},  {12, 82, 93, 121, 125, -1, -1},
      {7, 94, -1, -1, -1, -1, -1},  {0, 23, 82, 93, 109, 111, 123},
      {49, 51, 68, -1, -1, -1, -1},  {1, 16, 86, 97, 125, -1, -1},
      {11, 98, -1, -1, -1, -1, -1},  {4, 27, 86, 97, 113, 115, 127},
    };

  //copy the values of the temp transform positions to the global array
  std::copy( &tinverseTransformPositions[0][0], 
	     &tinverseTransformPositions[0][0]+128*7, 
	     &inverseTransformPositions[0][0] );

 //An array for looking up binary string representation of 4-bit ints
  std::string tdec2bin[16] = {"0000", "0001", "0010", "0011", 
			      "0100", "0101", "0110", "0111", 
			      "1000", "1001", "1010", "1011", 
			      "1100", "1101", "1110", "1111"};

  std::copy(tdec2bin, tdec2bin+16, dec2bin);  

  //Initialize the map of binary strings to their integer values
  bin2dec["0000"] = 0;
  bin2dec["0001"] = 1;
  bin2dec["0010"] = 2;
  bin2dec["0011"] = 3;
  bin2dec["0100"] = 4;
  bin2dec["0101"] = 5;
  bin2dec["0110"] = 6;
  bin2dec["0111"] = 7;
  bin2dec["1000"] = 8;
  bin2dec["1001"] = 9;
  bin2dec["1010"] = 10;
  bin2dec["1011"] = 11;
  bin2dec["1100"] = 12;
  bin2dec["1101"] = 13;
  bin2dec["1110"] = 14;
  bin2dec["1111"] = 15;

  //initialize k0 - k3
  k3 = 0; 
  k2 = 0; 
  k1 = 0;
  k0 = 0;  
  
  //initialize the size of the key to -1
  size = -1;

  //initialize the temporary sbox
  //the values in this sbox are flipped from those in the specification
  //as the state is little-endian during computation
  int tsBoxes[8][16] = 
    {
      {12, 7, 5, 14, 15, 2, 10, 9, 1, 11, 6, 0, 8, 4, 13, 3},
      {15, 8, 9, 6, 4, 7, 10, 12, 3, 13, 0, 11, 14, 1, 5, 2},
      {1, 11, 12, 0, 14, 7, 5, 10, 6, 8, 3, 13, 9, 2, 15, 4},
      {0, 11, 3, 5, 13, 4, 6, 10, 15, 8, 9, 14, 1, 2, 12, 7},
      {8, 4, 3, 9, 1, 2, 13, 14, 15, 10, 0, 7, 12, 5, 6, 11},
      {15, 0, 2, 11, 4, 7, 9, 14, 10, 12, 5, 6, 13, 1, 3, 8},
      {14, 7, 1, 11, 3, 8, 6, 5, 4, 9, 2, 12, 10, 15, 13, 0},
      {8, 14, 7, 9, 15, 3, 4, 10, 11, 2, 1, 12, 0, 5, 13, 6}
    };
      
  //copy to sbox
   std::copy( &tsBoxes[0][0], 
	     &tsBoxes[0][0]+8*16, 
	     &sBoxes[0][0] );

   //initialize temporary inverse sbox
   int tinverseSBoxes[8][16] = 
     {
       {11, 8, 5, 15, 13, 2, 10, 1, 12, 7, 6, 9, 0, 14, 3, 4},
       {10, 13, 15, 8, 4, 14, 3, 5, 1, 2, 6, 11, 7, 9, 12, 0},
       {3, 0, 13, 10, 15, 6, 8, 5, 9, 12, 7, 1, 2, 11, 4, 14},
       {0, 12, 13, 2, 5, 3, 6, 15, 9, 10, 7, 1, 14, 4, 11, 8},
       {10, 4, 5, 2, 1, 13, 14, 11, 0, 3, 9, 15, 12, 6, 7, 8},
       {1, 13, 2, 14, 4, 10, 11, 5, 15, 6, 8, 3, 9, 12, 7, 0},
       {15, 2, 10, 4, 8, 7, 6, 1, 5, 9, 12, 3, 11, 14, 0, 13},
       {12, 10, 9, 5, 6, 13, 15, 2, 0, 3, 7, 8, 11, 14, 1, 4},
     };

   //copy to inverse sbox
    std::copy( &tinverseSBoxes[0][0], 
	     &tinverseSBoxes[0][0]+8*16, 
	     &inverseSBoxes[0][0] );

  //The table of hexadecimal values. The value at each index is its 
  //hex representation
  hexTable = "0123456789abcdef";

}
 

//linearTransform used in non-bitslice mode
std::tuple< std::bitset<64>, std::bitset<64> >
Serpent::linearTransform(std::tuple< std::bitset<64>, std::bitset<64> > state){
  
  std::string stateString0 = std::get<0>(state).to_string();
  std::string stateString1 = std::get<1>(state).to_string();
  std::string stateString = stateString0.append(stateString1);
  stateString.append(1, '0');

  std::string tempState = "";
  unsigned char bit = '0';

  for ( int i = 0; i < 128; i ++ ){
    bit = '0';

    bit ^= ((stateString[transformPositions[i][0]]) - '0');
    bit ^= ((stateString[transformPositions[i][1]]) - '0');
    bit ^= ((stateString[transformPositions[i][2]]) - '0');
    bit ^= ((stateString[transformPositions[i][3]]) - '0');
    bit ^= ((stateString[transformPositions[i][4]]) - '0');
    bit ^= ((stateString[transformPositions[i][5]]) - '0');
    bit ^= ((stateString[transformPositions[i][6]]) - '0');

    tempState.append(1, bit);
  }
  std::get<0>(state) = std::bitset<64>(tempState.substr(0,64));
  std::get<1>(state) = std::bitset<64>(tempState.substr(64,64));
  return state;

}


//The inverse of the linear transformation. Used for decryption
std::tuple< std::bitset<64>, std::bitset<64> >
Serpent::inverseLinearTransform(std::tuple< std::bitset<64>, std::bitset<64> > state){

  std::string stateString0 = std::get<0>(state).to_string();
  std::string stateString1 = std::get<1>(state).to_string();
  std::string stateString = stateString0.append(stateString1);
  
  std::string tempState = "";
  
  for ( int i = 0; i < 128; i ++ ){
    unsigned char bit = '0';
    for ( int j = 0; j < 7; j ++ ){
     
      if (inverseTransformPositions[i][j] >= 0 ){
	int bit2 = ((stateString[inverseTransformPositions[i][j]]) - '0');
	bit ^= bit2;
      }
    }
    tempState.append(1, bit);
  }
  
  std::bitset<64> tempState0(tempState.substr(0,64));
  std::bitset<64> tempState1(tempState.substr(64,64));
  std::get<0>(state) = tempState0;
  std::get<1>(state) = tempState1;
  return state;
}


// Rotates to the left
void Serpent::rotate(std::bitset<32> &b, unsigned m) {
  b = (b >>  m | b << (32-m));
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
  
  unsigned char tempKey[size];
  int tempIndex = 0;

  for( int i = size-1; i >= 0; i-- ){
    tempKey[tempIndex] = userKey[i];
    tempIndex ++;
  }
  
  userKey = tempKey;
  
  if (size == 16){
      //k0 already equals 0;
    k1 = 1;
    k2 = readIn(userKey);
    k3 = readIn(userKey+8);
  }
  
  else if (size == 24){
    k0 = 1;
    k1 = readIn(userKey);
    k2 = readIn(userKey + 8);
    k3 = readIn(userKey + 16);
  }
 
  else if(size == 32){
    k0 = readIn(userKey);
    k1 = readIn(userKey + 8);
    k2 = readIn(userKey + 16);
    k3 = readIn(userKey + 24);
  }

  else{
    std::cout << "Key has not been set." << std::endl;
    std::cout << "SERPENT takes a 128, 192, or 256-bit key." << std::endl;
  }
    
   //4294967295 is the decimal representation of 32 bits of 1's
   //Using this as a mask to isolate 32 bits at a time.
   words[0] = std::bitset<32>(bitMirrorInt(k3 & (unsigned long int)4294967295));
   words[1] = std::bitset<32>(bitMirrorInt(k3 >> 32));
   words[2] = std::bitset<32>(bitMirrorInt(k2 & (unsigned long int)4294967295));
   words[3] = std::bitset<32>(bitMirrorInt(k2 >> 32));
   words[4] = std::bitset<32>(bitMirrorInt(k1 & (unsigned long int)4294967295));
   words[5] = std::bitset<32>(bitMirrorInt(k1 >> 32));
   words[6] = std::bitset<32>(bitMirrorInt(k0 & (unsigned long int)4294967295));
   words[7] = std::bitset<32>(bitMirrorInt(k0 >> 32));

   generateSubKeys();
}

  
/**
 * Generates the 33 128-subkeys to be used for encryption
 */
void Serpent::generateSubKeys(){
    
  //Populate the array of words. The first 8 words are not used in the
  //final subkeys, they're just used as the seed for generation of 
  //the 33 subkeys that will be used in the encryption algorithm
  for (int i = 8; i < 140; i++){
    
    //affine recurrence
    words[i] = (words[i-8] ^ words[i-5] ^ words[i-3] ^ words[i-1]
		^ std::bitset<32>(bitMirrorInt(i-8)) 
		^ std::bitset<32>(bitMirrorInt(phi)));
    
    //rotate "left"
    words[i] = ((words[i] >> 11) | (words[i] << 21));
  }

  //String array to store the output of the sboxes as the words 
  //are passed through them
  std::string preKeys[132];
  
  for ( int i = 0; i<33; i++ ){
 
    //iterate over the 32 bits of 4 words at a time
    //taking one bit from each and concatenating them to form a 4-bit value
    //which is then passed through the sboxes
    for ( int k = 0; k < 32; k++ ){

      //Take 1 bit from the same position from 4 words
      unsigned int sBoxInput = fourBitsFromWords(words[4*i + 8], 
						 words[4*i + 9],
						 words[4*i + 10], 
						 words[4*i + 11], k);
  
      //Run the bits from the 4 words through the sboxes, starting
      //with sbox 3 and going in descending order
      unsigned int resultInt = sBoxes[(35 - i)%8][sBoxInput];
      std::string result = dec2bin[resultInt];
    
      //the sbox output is then broken up by bit, with one bit appended
      //to the end of four different prekeys
      for ( int j = 0; j<4 ; j++ ){
	preKeys[j + 4*i] = preKeys[j+ 4*i] + result[j];
      }
    }
  }
  
  for ( int i = 0; i<33; i++ ){
    
    std::get<0>(subKeys[i]) = std::bitset<64>
      ( preKeys[4*i].append(preKeys[4*i + 1]));
   
    std::get<1>(subKeys[i]) = std::bitset<64>
      ( preKeys[4*i + 2].append(preKeys[4*i + 3]));
       
    subKeys[i] = initialP(subKeys[i]);
        
  }
}




//Sets the size to keyLength
//Must be called before setKey
void Serpent::setKeySize( int keyLength){
  size = keyLength;
}




//Returns this block cipher's key size in bytes.
// @return  Key size.
int Serpent::keySize (){
      
  if (size == -1){
    std::cout << "Keysize has not been set; returning 0." << std::endl;
    return 0;
      
  }else{
    return size;
  }
}

//Returns this block cipher's block size in bytes.
// @return Block size.

int Serpent::blockSize (){
  return 16;
}
 

//Passes the state through the given sbox
std::tuple< std::bitset<64>, std::bitset<64> > 
Serpent::SBitset ( int box, std::tuple< std::bitset<64>, std::bitset<64> > state ){

  int index;
  unsigned long long int lowerState = 0;
  unsigned long long int upperState = 0;
  std::bitset<64> state0 = std::get<0>(state);
  std::bitset<64> state1 = std::get<1>(state);

  int i;
  for( i = 0; i < 16; i ++ ){
    
    index = fourBits64(state0, 4*i);
    //index = bin2dec[state0.substr(4*i, 4)];
    lowerState ^= ((unsigned long long int)(sBoxes[box%8][index]) << 
		   (60 - (4*i)));
  }

  for( i = 16; i < 32; i ++ ){

    index = fourBits64(state1, (4*i - 64));
    //index = bin2dec[state1.substr(4*i - 64, 4)];
    upperState ^= ((unsigned long long int)(sBoxes[box%8][index]) << 
		   (60 - (4*i)));
  }

  std::get<0>(state) = std::bitset<64>(lowerState);
  std::get<1>(state) = std::bitset<64>(upperState);
  return state;

}

//Passes the state through the inverse of the given sbox  
 std::tuple < std::bitset<64>, std::bitset<64> >
 Serpent::inverseSBitset( int box, std::tuple< std::bitset<64>, 
					       std::bitset<64> >  state){
   
   int index;
   unsigned long long int lowerState = 0;
   unsigned long long int upperState = 0;
   
   for( int i = 0; i < 16; i ++ ){
     
     index = fourBits(state, 4*i);
     lowerState ^= ((unsigned long long int)(inverseSBoxes[box%8][index]) << 
		    (60 - (4*i)));
   }
   
   for( int i = 16; i < 32; i ++ ){
     
     index = fourBits(state, 4*i);
     upperState ^= ((unsigned long long int)(inverseSBoxes[box%8][index]) << 
		    (60 - (4*i)));
   }
   
   std::get<0>(state) = std::bitset<64>(lowerState);
   std::get<1>(state) = std::bitset<64>(upperState);
   return state;
  
 }


//Flips the bits of the given string, about the 16th bit
//For example, 1 -> 80000000 (in hex)
std::string Serpent::bitMirrorString( std::string image, 
			      std::string reflection = "" ){
  
  if ( image.length() <= 1 ){

    image.append(reflection);
    return image;
  }
 
  else {

    return bitMirrorString( image.substr( 1, image.length() - 1 ), 
		     reflection.insert(0, 1, image.front()));
  }
}


//Flips the bits of the given int, about the 16th bit
//For example, 1 -> 80000000 (in hex)
//int is assumed to "hold" 32 places
unsigned int Serpent::bitMirrorInt( unsigned int image ){
  
    image = (((image & 0xaaaaaaaa) >> 1) | 
		((image & 0x55555555) << 1));
    image = (((image & 0xcccccccc) >> 2) | 
		((image & 0x33333333) << 2));
    image = (((image & 0xf0f0f0f0) >> 4) | 
		((image & 0x0f0f0f0f) << 4));
    image = (((image & 0xff00ff00) >> 8) | 
		((image & 0x00ff00ff) << 8));
    image = (( image >> 16) | (image << 16));

    return image;
}

//Flips the bits of the given unsigned char
unsigned char Serpent::bitMirrorByte( unsigned char image) {

  unsigned int imageInt = static_cast<unsigned int>(image);
  imageInt = (imageInt & 0xaa) >> 1 | (imageInt & 0x55) << 1;
  imageInt = (imageInt & 0xcc) >> 2 | (imageInt & 0x33) << 2;
  imageInt = (imageInt & 0xf0) >> 4 | (imageInt & 0x0f) << 4;

  unsigned char mirrored = static_cast<unsigned char>(imageInt);
  return mirrored;
}


//Flips the bits of the given bitset, about the 16th bit
//For example, 1 -> 80000000 (in hex)
//image is a bitset of size 32
std::bitset<32> Serpent::bitMirrorBitset( std::bitset<32> image ){

  std::string str = image.to_string();
  str = bitMirrorString( str, "" );
  return std::bitset<32>(str);

}

// Return a tuple of 64 bit bitsets with bits in reverse order of those
// in the argument
std::tuple< std::bitset<64>, std::bitset<64> > 
Serpent::bitMirrorTuple ( std::tuple< std::bitset<64>, std::bitset<64> > image ){
  
  std::string str0 = (std::get<1>(image)).to_string();
  std::string str1 = (std::get<0>(image)).to_string();
  str0 = bitMirrorString(str0, "");
  std::bitset<64> tempSet (str0);
  std::get<0>(image) = tempSet;
  

  str1 = bitMirrorString(str1, "");
  std::bitset<64> tempSet1 (str1);
  std::get<1>(image) = tempSet1;
  
  return image;
}

//Returns the int value of four bits from the given bitset of length 64
unsigned int Serpent::fourBits64 (std::bitset<64> halfstate, int pos){

  return ((halfstate.to_ullong() >> (60 - pos)) & 15);

}


//Returns the int value of four bits from word, beginning at the specified
// position 
unsigned int Serpent::fourBits
( std::tuple< std::bitset<64>, std::bitset<64> > state, int pos ){

  unsigned int intVal;
  
  if(pos < 64){
    intVal = ((unsigned long long int)(std::get<0>(state).to_ulong()) 
	      >> (60 - pos)) & 15;
      }
  else{
    intVal = ((unsigned long long int)(std::get<1>(state).to_ulong()) 
	      >> (60 - (pos - 64))) & 15;
  }
  return intVal;

}

// Returns a binary string formed from the bit at pos of each of the four
// word arguments. The leftmost bit comes from the first argument, the second
// leftmost bit from the second argument and so on.
unsigned int Serpent::fourBitsFromWords( std::bitset<32> word0,
					 std::bitset<32> word1,
					 std::bitset<32> word2,
					 std::bitset<32> word3, int pos ){

  std::bitset<4> bitsFromWords;
  bitsFromWords[3] = word0[31-pos];
  bitsFromWords[2] = word1[31-pos];
  bitsFromWords[1] = word2[31-pos];
  bitsFromWords[0] = word3[31-pos];

  return (unsigned int)(bitsFromWords.to_ulong());
}


// Returns a hex string representation of the state
std::string Serpent::hexString (std::tuple< std::bitset<64>, std::bitset<64> > state){

  std::string hexVal = "";
  int index;
  std::bitset<64> state0 = std::get<0>(state);
  std::bitset<64> state1 = std::get<1>(state);

  int i;
  
  for ( i = 0; i<16; i ++ ){
    index = (int)(fourBits64(state0, 4*i));
    hexVal.append(1, hexTable[index]);
  }

  for ( i = 16; i < 32; i++ ){
    index = int(fourBits64(state1, (4*i - 64)));
    hexVal.append(1, hexTable[index]);
  }

  return hexVal;
}

//Nessify output hexstring so that is reads sensibly    
std::string Serpent::nessify (std::string reformat){

  std::string nessied = "";
  for ( unsigned int i = 0; i < reformat.length(); i+=2 ){
    
    nessied = nessied.insert(0, 1, reformat[i+1]);
    nessied = nessied.insert(0, 1, reformat[i]);
    
  } 
  return nessied;
}


//Prints the current state in big-endian hex
void Serpent::printState 
(std::tuple< std::bitset<64>, std::bitset<64> > string){

  std::tuple< std::bitset<64>, std::bitset<64> > toPrint 
    = bitMirrorTuple(string);

  std::cout << hexString(toPrint) << std::endl;

}


//Reads bytes into an unsigned long long int
//bytes[] must have length 8
unsigned long long int Serpent::readIn ( unsigned char bytes[8] ){
      
  unsigned long long int intVal = 0;
  
  for (int i = 0; i<8; i++){
    intVal ^= ((long long int)bytes[i] << (56 - (8*i)));
  }
  
  return intVal;
}


//Inverse initial permutation
std::tuple< std::bitset<64>, std::bitset<64> >
Serpent::initialP ( std::tuple< std::bitset<64>, 
				     std::bitset<64> > state ){

  std::bitset<64> state0 (std::get<0>(state));
  std::bitset<64> state1 (std::get<1>(state));
  
  std::bitset<64> tempState0;
  std::bitset<64> tempState1;
  
  for ( int i = 0; i < 128; i++ ){
        
    if (i < 64){
      
      if ( ip[i] < 64 ){
	tempState0[63-i] = state0[63-ip[i]];
      }
      else{
	tempState0[63-i] = state1[63-(ip[i] - 64)];
      }
    }
    else{
      if (ip[i] > 63){
	tempState1[127 - i] = state1[63 -(ip[i] - 64)];
      }
      else {
	tempState1[127 - i] = state0[63 - ip[i]];
      }
    }
  }
  std::get<0>(state) = tempState0;
  std::get<1>(state) = tempState1;
  return state;
}

//Final permutation
std::tuple< std::bitset<64>, std::bitset<64> >
Serpent::finalP ( std::tuple< std::bitset<64>, 
				     std::bitset<64> > state ){

  std::bitset<64> state0 (std::get<0>(state));
  std::bitset<64> state1 (std::get<1>(state));
  
  std::bitset<64> tempState0;
  std::bitset<64> tempState1;
  
  for ( int i = 0; i < 128; i++ ){
    
    if (i < 64){
      if ( fp[i] < 64 ){
	tempState0[63-i] = state0[63-fp[i]];
      }
      else{
	tempState0[63-i] = state1[63-(fp[i] - 64)];
      }
    }
    else{
      if (fp[i] > 63){
	tempState1[127 - i] = state1[63 -(fp[i] - 64)];
      }
      else {
	tempState1[127 - i] = state0[63 - fp[i]];
      }
    }
  }
  std::get<0>(state) = tempState0;
  std::get<1>(state) = tempState1;
  return state;
}
 

//Encrypt text
void Serpent::encrypt( unsigned char * text ){

  //Correct format issues
  for( int i = 0; i < 16; i++ ){
    text[i] = bitMirrorByte(text[i]);
  }

  unsigned long long int stateMSB = readIn(text);
  unsigned long long int stateLSB = readIn(text + 8);
      
  std::tuple< std::bitset<64>, std::bitset<64> > state;
  std::get<0>(state) = stateMSB;
  std::get<1>(state) = stateLSB;
  std::tuple< std::bitset<64>, std::bitset<64> > tempState;

  //Initial permutation
  state = initialP(state);
  
  for ( int round = 0; round < 31; round ++ ){
    
    //Xor with key
    std::get<0>(state) = (std::get<0>(subKeys[round]) ^ std::get<0>(state));
    std::get<1>(state) = (std::get<1>(subKeys[round]) ^ std::get<1>(state));
      
    //Sbox
    state = SBitset( round, state);
   
    //Linear transformation
    state = linearTransform(state);
   
  }
  
  //Xor with key  
  std::get<0>(state) = (std::get<0>(subKeys[31]) ^ std::get<0>(state));
  std::get<1>(state) = (std::get<1>(subKeys[31]) ^ std::get<1>(state));
  
  //Sbox
  state = SBitset( 7, state);
  
  //Xor with key
  std::get<0>(state) = (std::get<0>(subKeys[32]) ^ std::get<0>(state));
  std::get<1>(state) = (std::get<1>(subKeys[32]) ^ std::get<1>(state));

  //Final permutation
  state = finalP(state);
  //printState(state);

  std::string nessieOutput = nessify(hexString(bitMirrorTuple(state)));
  std::cout << "Ciphertext: " << nessieOutput << std::endl;

}

void Serpent::decrypt ( unsigned char * text ){
   
  unsigned char tempText[16] = {};

  for( int i = 0; i <=15; i++ ){
    tempText[i] = bitMirrorByte(text[i]);
  }

  unsigned long long int stateMSB = readIn(tempText);
  unsigned long long int stateLSB = readIn(tempText + 8);

  std::tuple< std::bitset<64>, std::bitset<64> > state;
  std::get<0>(state) = stateMSB;
  std::get<1>(state) = stateLSB;
  std::tuple< std::bitset<64>, std::bitset<64> > tempState;


  //Initial permutation
  //NB the final permutation is the inverse of the initial permutation 
  //so new functions weren't needed and were removed
  state = initialP(state);

  //Xor with key
  std::get<0>(state) = (std::get<0>(subKeys[32]) ^ std::get<0>(state));
  std::get<1>(state) = (std::get<1>(subKeys[32]) ^ std::get<1>(state));


  //Inverse sbox
  state = inverseSBitset(7, state);

  //Xor with subkey
  std::get<0>(state) = (std::get<0>(subKeys[31]) ^ std::get<0>(state));
  std::get<1>(state) = (std::get<1>(subKeys[31]) ^ std::get<1>(state));
  

  for ( int round = 30; round >= 0; round -- ){

    //Inverse linear transform
    state = inverseLinearTransform(state);
   
    //Inverse sbox
    state = inverseSBitset(round, state);

    //Xor with key
    std::get<0>(state) = (std::get<0>(subKeys[round]) ^ std::get<0>(state));
    std::get<1>(state) = (std::get<1>(subKeys[round]) ^ std::get<1>(state));


  }
    
  state = finalP(state);

  std::string nessieOutput = nessify(hexString(bitMirrorTuple(state)));
  std::cout << "Plaintext: " << nessieOutput << std::endl;

}


 
int main(int argc, char** argv)
 {
   std::string usageWarning =  "usage: [-i/--input fileName] [-o/--output fileName] [-k/--key 32bitKey] [-n/--nonce numEncryptions]";
   int nonce = 1;
   std::string inputFile;
   std::string outputFile;
   std::string key;
   bool hasInputFile = false;
   bool hasOutputFile = false;
  bool hasKey = false;
  std::ofstream out;
  std::streambuf *coutbuf;
  
  if (argc < 2) {
    std::cerr << usageWarning << std::endl;
    return 1;
  }

  //Parse command line input
  for( int i = 1; i < argc; i++ ) {
    if (0 == strncmp(argv[i], "-n", 2) || 0 == strncmp(argv[i], "--nonce", 7)) {
i = i + 1;
      nonce = std::stof(argv[i]);
    }
    else if (0 == strncmp(argv[i], "-i", 2) || 0 == strncmp(argv[i], "--input", 7)) {
      i = i + 1;
      inputFile = argv[i];
      hasInputFile = true;
    }
    else if (0 == strncmp(argv[i], "-o", 2) || 0 == strncmp(argv[i], "--output", 8)) {
      i = i + 1;
      outputFile = argv[i];
      out.open(outputFile);
      coutbuf = std::cout.rdbuf(); //save old buf
      std::cout.rdbuf(out.rdbuf()); 
      hasOutputFile = true;
    }
    else if (0 == strncmp(argv[i], "-k", 2) || 0 == strncmp(argv[i], "--key", 5)) {
      i = i + 1;
      key = argv[i];
      hasKey = true;
    }
    else {
      std::cerr << "Unrecognized option." << std::endl;
      std::cerr << usageWarning << std::endl;
      return 1;
    }

  }
  
  Serpent serpent; 

 unsigned char testKey[] = {0x00, 0x00, 0x00, 0x00, 
			    0x00, 0x00, 0x00, 0x00, 
			    0x00, 0x00, 0x00, 0x00, 
			    0x00, 0x00, 0x00, 0x00};
 
 unsigned char plaintext[16] = 
   {0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00};

 if (hasKey) {
   unsigned char new_key[32];
   int index = 0;
   for (int i = 0; i < key.length() - 2; i++) {
     std::stringstream ss;
     ss << std::hex << key[i] << key[i+1];
     int n;
     ss >> n;
     unsigned char x = (unsigned char)n;
     new_key[index] = x;
     index += 1;
     i += 1;
   }
   memcpy(testKey, new_key, sizeof(testKey));
 }

 if (hasInputFile) {
    unsigned char new_plaintext[16];

    std::ifstream in(inputFile);
    unsigned char  x;
    int index = 0;
        int temp;
    std::string temp_string = "";

    while (in >> std::noskipws >> x) {

      std::cout << "X: " << std::hex << x << std::endl;
      temp_string += x;

      if (temp_string.length() == 2) {
        std::stringstream ss;
        ss << std::hex << temp_string;
        int n;
        ss >> n;
        unsigned char y = (unsigned char)n;
        new_plaintext[index] = y;
        index += 1;
        temp_string = "";
      }
    }
    memcpy(plaintext, new_plaintext, sizeof(plaintext));  // Set plaintext to be the plaintext we read in from file
 }
 else {
 }


 serpent.setKeySize(sizeof(testKey)/sizeof(*testKey));
 serpent.setKey(testKey);
 serpent.generateSubKeys();

 std::cout << "TESTING" << std::endl;
 int encryptionRound = 0;
 while (encryptionRound < nonce) {
   std::cout << std::dec << "================================ ROUND " << encryptionRound << " ================================\n" << std::endl;
   serpent.encrypt(plaintext);
   std::cout << std::dec << "============================ END ROUND " << encryptionRound << " ============================\n"<< std::endl;
   encryptionRound++;
  
 }

 std::cout.rdbuf(coutbuf);

 if (hasOutputFile){
   out.close();
 }
 
 return 0;
 
 }


