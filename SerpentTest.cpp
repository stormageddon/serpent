#include <algorithm>
#include <cstdio>
#include <iostream>
#include <bitset>
#include <map>
#include <string>
#include <cstring>
#include <utility>
#include <tuple>
class Serpent
{
  
  
private:
  
  int ip[128];
  int fp[128];
  const char * hexTable;

  int size;
  unsigned long long int k0;
  unsigned long long int k1;
  unsigned long long int k2;
  unsigned long long int k3;
  std::bitset<32> words[140];
  
  std::tuple< std::bitset<64>, std::bitset<64> > subKeys[33];
  std::string bitSliceResult[4];
  static const unsigned long int phi = 2654435769;
  
  int sBoxDecimalTable[8][16];
  int transformTable[128][7];
  int inverseTransformTable[128][7];
  
  std::map<std::string, std::string> sBoxBitstring[8];
  std::map<std::string, std::string> sBoxBitstringInverse[8];
  
public:                    // begin public section
  
  Serpent();
  
  std::tuple< std::bitset<64>, std::bitset<64> >
  linearTransformBitSlice(std::tuple< std::bitset<64>, std::bitset<64> > state);

  std::tuple< std::bitset<64>, std::bitset<64> >
  linearTransform(std::tuple< std::bitset<64>, std::bitset<64> > state);

  std::tuple< std::bitset<64>, std::bitset<64> >
  inverseLinearTransform(std::tuple< std::bitset<64>, std::bitset<64> > state);

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

  unsigned int SInt(int box, unsigned int input);

  std::tuple< std::bitset<64>, std::bitset<64> > 
  SBitset( int box,  std::tuple< std::bitset<64>, std::bitset<64> > bitState );

  std::string SInverse(int box, std::string output);

  std::tuple < std::bitset<64>, std::bitset<64> >
  inverseSBitset( int box, std::tuple< std::bitset<64>, std::bitset<64> > 
		  bitState);

  std::string SHat(int box, std::string input);

  std::string SHatInverse(int box, std::string output);

  std::string * SBitslice(int box, std::string words[4]);

  std::string * SBitsliceInverse(int box, std::string words[][32]);

  std::string bitMirrorString (std::string image, std::string reflection);

  unsigned int bitMirrorInt ( unsigned int image );

  unsigned char bitMirrorByte( unsigned char image);

  std::bitset<32> bitMirrorBitset ( std::bitset<32> image );

  std::tuple< std::bitset<64>, std::bitset<64> > 
  bitMirrorTuple ( std::tuple< std::bitset<64>, std::bitset<64> > image );

  unsigned int fourBits ( std::bitset<32> word, int pos );

  unsigned int fourBitsFromWords ( std::bitset<32> word0, 
				   std::bitset<32> word1, 
				   std::bitset<32> word2, 
				   std::bitset<32> word3,
				   int pos);

  std::string fourBitsString( std::bitset<64> words, int pos );

  std::string hexString (std::tuple< std::bitset<64>, std::bitset<64> > string);

  std::string nessify (std::string reformat);

  std::string unnessify (std::string reformat);

  void printState (std::tuple< std::bitset<64>, std::bitset<64> > string);

  void printStateBinary (std::tuple< std::bitset<64>, std::bitset<64> > string);

  unsigned long long int readIn ( unsigned char bytes[8] );

  std::tuple< std::bitset<64>, std::bitset<64> > 
  initialP ( std::tuple< std::bitset<64>, std::bitset<64> > state );
  
  std::tuple< std::bitset<64>, std::bitset<64> >
  inverseIP ( std::tuple< std::bitset<64>, std::bitset<64> > state );
  
  std::tuple< std::bitset<64>, std::bitset<64> > 
  finalP ( std::tuple< std::bitset<64>, std::bitset<64> > state );
  
  std::tuple< std::bitset<64>, std::bitset<64> >
  inverseFP ( std::tuple< std::bitset<64>, std::bitset<64> > state );
  
  void encrypt( unsigned char * text );

  void decrypt ( unsigned char * text );
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


   int tfp[128] = 
     {0, 4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 56, 60,
      64, 68, 72, 76, 80, 84, 88, 92, 96, 100, 104, 108, 112, 116, 120, 124,
      1, 5, 9, 13, 17, 21, 25, 29, 33, 37, 41, 45, 49, 53, 57, 61, 
      65, 69, 73, 77, 81, 85, 89, 93, 97, 101, 105, 109, 113, 117, 121, 125,
      2, 6, 10, 14, 18, 22, 26, 30, 34, 38, 42, 46, 50, 54, 58, 62, 
      66, 70, 74, 78, 82, 86, 90, 94, 98, 102, 106, 110, 114, 118, 122, 126,
      3, 7, 11, 15, 19, 23, 27, 31, 35, 39, 43, 47, 51, 55, 59, 63,
      67, 71, 75, 79, 83, 87, 91, 95, 99, 103, 107, 111, 115, 119, 123, 127};

  
  std::copy(tfp, tfp+128, fp);  


  int ttransformTable[128][7] = 
    {
      {16, 52, 56, 70, 83, 94, 105},
      {72, 114, 125, -1, -1, -1, -1},
      {2, 9, 15, 30, 76, 84, 126},
      {36, 90, 103, -1, -1, -1, -1},
      {20, 56, 60, 74, 87, 98, 109},
      {1, 76, 118, -1, -1, -1, -1},
      {2, 6, 13, 19, 34, 80, 88},
      {40, 94, 107, -1, -1, -1, -1},
      {24, 60, 64, 78, 91, 102, 113},
      {5, 80, 122, -1, -1, -1, -1},
      {6, 10, 17, 23, 38, 84, 92},
      {44, 98, 111, -1, -1, -1, -1},
      {28, 64, 68, 82, 95, 106, 117},
      {9, 84, 126, -1, -1, -1, -1},
      {10, 14, 21, 27, 42, 88, 96},
      {48, 102, 115, -1, -1, -1, -1},
      {32, 68, 72, 86, 99, 110, 121},
      {2, 13, 88, -1, -1, -1, -1},
      {14, 18, 25, 31, 46, 92, 100},
      {52, 106, 119, -1, -1, -1, -1},
      {36, 72, 76, 90, 103, 114, 125},
      {6, 17, 92, -1, -1, -1, -1},
      {18, 22, 29, 35, 50, 96, 104},
      {56, 110, 123, -1, -1, -1, -1},
      {1, 40, 76, 80, 94, 107, 118},
      {10, 21, 96, -1, -1, -1, -1},
      {22, 26, 33, 39, 54, 100, 108},
      {60, 114, 127, -1, -1, -1, -1},
      {5, 44, 80, 84, 98, 111, 122},
      {14, 25, 100, -1, -1, -1, -1},
      {26, 30, 37, 43, 58, 104, 112},
      {3, 118, -1, -1, -1, -1, -1},
      {9, 48, 84, 88, 102, 115, 126},
      {18, 29, 104, -1, -1, -1, -1},
      {30, 34, 41, 47, 62, 108, 116},
      {7, 122, -1, -1, -1, -1, -1},
      {2, 13, 52, 88, 92, 106, 119},
      {22, 33, 108, -1, -1, -1, -1},
      {34, 38, 45, 51, 66, 112, 120},
      {11, 126, -1, -1, -1, -1, -1},
      {6, 17, 56, 92, 96, 110, 123},
      {26, 37, 112, -1, -1, -1, -1},
      {38, 42, 49, 55, 70, 116, 124},
      {2, 15, 76, -1, -1, -1, -1},
      {10, 21, 60, 96, 100, 114, 127},
      {30, 41, 116, -1, -1, -1, -1},
      {0, 42, 46, 53, 59, 74, 120},
      {6, 19, 80, -1, -1, -1, -1},
      {3, 14, 25, 100, 104, 118, -1},
      {34, 45, 120, -1, -1, -1, -1},
      {4, 46, 50, 57, 63, 78, 124},
      {10, 23, 84, -1, -1, -1, -1},
      {7, 18, 29, 104, 108, 122, -1},
      {38, 49, 124, -1, -1, -1, -1},
      {0, 8, 50, 54, 61, 67, 82},
      {14, 27, 88, -1, -1, -1, -1},
      {11, 22, 33, 108, 112, 126, -1},
      {0, 42, 53, -1, -1, -1, -1},
      {4, 12, 54, 58, 65, 71, 86},
      {18, 31, 92, -1, -1, -1, -1},
      {2, 15, 26, 37, 76, 112, 116},
      {4, 46, 57, -1, -1, -1, -1},
      {8, 16, 58, 62, 69, 75, 90},
      {22, 35, 96, -1, -1, -1, -1},
      {6, 19, 30, 41, 80, 116, 120},
      {8, 50, 61, -1, -1, -1, -1},
      {12, 20, 62, 66, 73, 79, 94},
      {26, 39, 100, -1, -1, -1, -1},
      {10, 23, 34, 45, 84, 120, 124},
      {12, 54, 65, -1, -1, -1, -1},
      {16, 24, 66, 70, 77, 83, 98},
      {30, 43, 104, -1, -1, -1, -1},
      {0, 14, 27, 38, 49, 88, 124},
      {16, 58, 69, -1, -1, -1, -1},
      {20, 28, 70, 74, 81, 87, 102},
      {34, 47, 108, -1, -1, -1, -1},
      {0, 4, 18, 31, 42, 53, 92},
      {20, 62, 73, -1, -1, -1, -1},
      {24, 32, 74, 78, 85, 91, 106},
      {38, 51, 112, -1, -1, -1, -1},
      {4, 8, 22, 35, 46, 57, 96},
      {24, 66, 77, -1, -1, -1, -1},
      {28, 36, 78, 82, 89, 95, 110},
      {42, 55, 116, -1, -1, -1, -1},
      {8, 12, 26, 39, 50, 61, 100},
      {28, 70, 81, -1, -1, -1, -1},
      {32, 40, 82, 86, 93, 99, 114},
      {46, 59, 120, -1, -1, -1, -1},
      {12, 16, 30, 43, 54, 65, 104},
      {32, 74, 85, -1, -1, -1, -1},
      {36, 90, 103, 118, -1, -1, -1},
      {50, 63, 124, -1, -1, -1, -1},
      {16, 20, 34, 47, 58, 69, 108},
      {36, 78, 89, -1, -1, -1, -1},
      {40, 94, 107, 122, -1, -1, -1},
      {0, 54, 67, -1, -1, -1, -1},
      {20, 24, 38, 51, 62, 73, 112},
      {40, 82, 93, -1, -1, -1, -1},
      {44, 98, 111, 126, -1, -1, -1},
      {4, 58, 71, -1, -1, -1, -1},
      {24, 28, 42, 55, 66, 77, 116},
      {44, 86, 97, -1, -1, -1, -1},
      {2, 48, 102, 115, -1, -1, -1},
      {8, 62, 75, -1, -1, -1, -1},
      {28, 32, 46, 59, 70, 81, 120},
      {48, 90, 101, -1, -1, -1, -1},
      {6, 52, 106, 119, -1, -1, -1},
      {12, 66, 79, -1, -1, -1, -1},
      {32, 36, 50, 63, 74, 85, 124},
      {52, 94, 105, -1, -1, -1, -1},
      {10, 56, 110, 123, -1, -1, -1},
      {16, 70, 83, -1, -1, -1, -1},
      {0, 36, 40, 54, 67, 78, 89},
      {56, 98, 109, -1, -1, -1, -1},
      {14, 60, 114, 127, -1, -1, -1},
      {20, 74, 87, -1, -1, -1, -1},
      {4, 40, 44, 58, 71, 82, 93},
      {60, 102, 113, -1, -1, -1, -1},
      {3, 18, 72, 114, 118, 125, -1},
      {24, 78, 91, -1, -1, -1, -1},
      {8, 44, 48, 62, 75, 86, 97},
      {64, 106, 117, -1, -1, -1, -1},
      {1, 7, 22, 76, 118, 122, -1},
      {28, 82, 95, -1, -1, -1, -1},
      {12, 48, 52, 66, 79, 90, 101},
      {68, 110, 121, -1, -1, -1, -1},
      {5, 11, 26, 80, 122, 126, -1},
      {32, 86, 99, -1, -1, -1, -1},
    };
  
  std::copy( &ttransformTable[0][0], &ttransformTable[0][0]+128*7, 
	     &transformTable[0][0] );
  
  int tinverseTransformTable[128][7]  = 
    {
      {53, 55, 72, -1, -1, -1, -1},
      {1, 5, 20, 90, -1, -1, -1},
      {15, 102, -1, -1, -1, -1, -1},
      {3, 31, 90, -1, -1, -1, -1},
      {57, 59, 76, -1, -1, -1, -1},
      {5, 9, 24, 94, -1, -1, -1},
      {19, 106, -1, -1, -1, -1, -1},
      {7, 35, 94, -1, -1, -1, -1},
      {61, 63, 80, -1, -1, -1, -1},
      {9, 13, 28, 98, -1, -1, -1},
      {23, 110, -1, -1, -1, -1, -1},
      {11, 39, 98, -1, -1, -1, -1},
      {65, 67, 84, -1, -1, -1, -1},
      {13, 17, 32, 102, -1, -1, -1},
      {27, 114, -1, -1, -1, -1, -1},
      {1, 3, 15, 20, 43, 102, -1},
      {69, 71, 88, -1, -1, -1, -1},
      {17, 21, 36, 106, -1, -1, -1},
      {1, 31, 118, -1, -1, -1, -1},
      {5, 7, 19, 24, 47, 106, -1},
      {73, 75, 92, -1, -1, -1, -1},
      {21, 25, 40, 110, -1, -1, -1},
      {5, 35, 122, -1, -1, -1, -1},
      {9, 11, 23, 28, 51, 110, -1},
      {77, 79, 96, -1, -1, -1, -1},
      {25, 29, 44, 114, -1, -1, -1},
      {9, 39, 126, -1, -1, -1, -1},
      {13, 15, 27, 32, 55, 114, -1},
      {81, 83, 100, -1, -1, -1, -1},
      {1, 29, 33, 48, 118, -1, -1},
      {2, 13, 43, -1, -1, -1, -1},
      {1, 17, 19, 31, 36, 59, 118},
      {85, 87, 104, -1, -1, -1, -1},
      {5, 33, 37, 52, 122, -1, -1},
      {6, 17, 47, -1, -1, -1, -1},
      {5, 21, 23, 35, 40, 63, 122},
      {89, 91, 108, -1, -1, -1, -1},
      {9, 37, 41, 56, 126, -1, -1},
      {10, 21, 51, -1, -1, -1, -1},
      {9, 25, 27, 39, 44, 67, 126},
      {93, 95, 112, -1, -1, -1, -1},
      {2, 13, 41, 45, 60, -1, -1},
      {14, 25, 55, -1, -1, -1, -1},
      {2, 13, 29, 31, 43, 48, 71},
      {97, 99, 116, -1, -1, -1, -1},
      {6, 17, 45, 49, 64, -1, -1},
      {18, 29, 59, -1, -1, -1, -1},
      {6, 17, 33, 35, 47, 52, 75},
      {101, 103, 120, -1, -1, -1, -1},
      {10, 21, 49, 53, 68, -1, -1},
      {22, 33, 63, -1, -1, -1, -1},
      {10, 21, 37, 39, 51, 56, 79},
      {105, 107, 124, -1, -1, -1, -1},
      {14, 25, 53, 57, 72, -1, -1},
      {26, 37, 67, -1, -1, -1, -1},
      {14, 25, 41, 43, 55, 60, 83},
      {0, 109, 111, -1, -1, -1, -1},
      {18, 29, 57, 61, 76, -1, -1},
      {30, 41, 71, -1, -1, -1, -1},
      {18, 29, 45, 47, 59, 64, 87},
      {4, 113, 115, -1, -1, -1, -1},
      {22, 33, 61, 65, 80, -1, -1},
      {34, 45, 75, -1, -1, -1, -1},
      {22, 33, 49, 51, 63, 68, 91},
      {8, 117, 119, -1, -1, -1, -1},
      {26, 37, 65, 69, 84, -1, -1},
      {38, 49, 79, -1, -1, -1, -1},
      {26, 37, 53, 55, 67, 72, 95},
      {12, 121, 123, -1, -1, -1, -1},
      {30, 41, 69, 73, 88, -1, -1},
      {42, 53, 83, -1, -1, -1, -1},
      {30, 41, 57, 59, 71, 76, 99},
      {16, 125, 127, -1, -1, -1, -1},
      {34, 45, 73, 77, 92, -1, -1},
      {46, 57, 87, -1, -1, -1, -1},
      {34, 45, 61, 63, 75, 80, 103},
      {1, 3, 20, -1, -1, -1, -1},
      {38, 49, 77, 81, 96, -1, -1},
      {50, 61, 91, -1, -1, -1, -1},
      {38, 49, 65, 67, 79, 84, 107},
      {5, 7, 24, -1, -1, -1, -1},
      {42, 53, 81, 85, 100, -1, -1},
      {54, 65, 95, -1, -1, -1, -1},
      {42, 53, 69, 71, 83, 88, 111},
      {9, 11, 28, -1, -1, -1, -1},
      {46, 57, 85, 89, 104, -1, -1},
      {58, 69, 99, -1, -1, -1, -1},
      {46, 57, 73, 75, 87, 92, 115},
      {13, 15, 32, -1, -1, -1, -1},
      {50, 61, 89, 93, 108, -1, -1},
      {62, 73, 103, -1, -1, -1, -1},
      {50, 61, 77, 79, 91, 96, 119},
      {17, 19, 36, -1, -1, -1, -1},
      {54, 65, 93, 97, 112, -1, -1},
      {66, 77, 107, -1, -1, -1, -1},
      {54, 65, 81, 83, 95, 100, 123},
      {21, 23, 40, -1, -1, -1, -1},
      {58, 69, 97, 101, 116, -1, -1},
      {70, 81, 111, -1, -1, -1, -1},
      {58, 69, 85, 87, 99, 104, 127},
      {25, 27, 44, -1, -1, -1, -1},
      {62, 73, 101, 105, 120, -1, -1},
      {74, 85, 115, -1, -1, -1, -1},
      {3, 62, 73, 89, 91, 103, 108},
      {29, 31, 48, -1, -1, -1, -1},
      {66, 77, 105, 109, 124, -1, -1},
      {78, 89, 119, -1, -1, -1, -1},
      {7, 66, 77, 93, 95, 107, 112},
      {33, 35, 52, -1, -1, -1, -1},
      {0, 70, 81, 109, 113, -1, -1},
      {82, 93, 123, -1, -1, -1, -1},
      {11, 70, 81, 97, 99, 111, 116},
      {37, 39, 56, -1, -1, -1, -1},
      {4, 74, 85, 113, 117, -1, -1},
      {86, 97, 127, -1, -1, -1, -1},
      {15, 74, 85, 101, 103, 115, 120},
      {41, 43, 60, -1, -1, -1, -1},
      {8, 78, 89, 117, 121, -1, -1},
      {3, 90, -1, -1, -1, -1, -1},
      {19, 78, 89, 105, 107, 119, 124},
      {45, 47, 64, -1, -1, -1, -1},
      {12, 82, 93, 121, 125, -1, -1},
      {7, 94, -1, -1, -1, -1, -1},
      {0, 23, 82, 93, 109, 111, 123},
      {49, 51, 68, -1, -1, -1, -1},
      {1, 16, 86, 97, 125, -1, -1},
      {11, 98, -1, -1, -1, -1, -1},
      {4, 27, 86, 97, 113, 115, 127},
    };

  std::copy( &tinverseTransformTable[0][0], &tinverseTransformTable[0][0]+128*7, 
	     &inverseTransformTable[0][0] );
  
  k3 = 0; 
  k2 = 0; 
  k1 = 0;
  k0 = 0;  
  
  size = -1;
  /*
  int t[8][16] = {
    { 12, 1, 15, 8, 5, 6, 10, 13, 7, 10, 2, 4, 14, 0, 9, 3},
    { 15, 3, 4, 14, 9, 0, 10, 5, 8, 13, 7, 1, 6, 11, 12, 2},
    { 1, 6, 14, 9, 12, 3, 5, 15, 11, 8, 7, 2, 0, 13, 10, 4},
    { 0, 15, 13, 1, 3, 9, 6, 12, 11, 8, 4, 2, 5, 14, 10, 7},
    { 8, 15, 1, 12, 3, 0, 13, 6, 4, 10, 2, 5, 9, 7, 14, 11},
    { 15, 10, 4, 13, 2, 5, 9, 3, 0, 12, 7, 1, 11, 6, 14, 8},
    { 14, 4, 3, 10, 1, 2, 6, 13, 7, 9, 8, 15, 11, 12, 5, 0},
    { 8, 11, 15, 0, 7, 1, 4, 13, 14, 2, 3, 5, 9, 12, 10, 6},
  };
  */  

  hexTable = "0123456789abcdef";

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

std::tuple< std::bitset<64>, std::bitset<64> > Serpent::linearTransformBitSlice 
(std::tuple< std::bitset<64>, std::bitset<64> > state){
  
  std::string temp0 = std::get<0>(state).to_string();
  std::string temp1 = std::get<1>(state).to_string();
  
  std::bitset<32> x0 (temp0.substr(0, 32));
  std::bitset<32> x1 (temp0.substr(32, 32));
  std::bitset<32> x2 (temp1.substr(0, 32));
  std::bitset<32> x3 (temp1.substr(32, 32));

   rotate(x0, 13);
 
  
  rotate(x2, 3);
  x1 = x1^x0^x2;
 
  x3 = x3^x2^(x0 >> 3);
 
  rotate(x1, 1);
  rotate(x3, 7);
  x0 = x0^x1^x3;
 
  x2 = x2^x3^(x1 >> 7);
  rotate(x0, 5);
  rotate(x2, 22);
    
  std::get<0>(state) = std::bitset<64>((x0.to_string()).append(x1.to_string()));
  std::get<1>(state) = std::bitset<64>((x2.to_string()).append(x3.to_string()));

  return state;

}

//linearTransform used in non-bitslice mode
std::tuple< std::bitset<64>, std::bitset<64> >
Serpent::linearTransform(std::tuple< std::bitset<64>, std::bitset<64> > state){
  
  std::string stateString0 = std::get<0>(state).to_string();
  std::string stateString1 = std::get<1>(state).to_string();
  std::string stateString = stateString0.append(stateString1);
  std::string tempState = "";
  
  for ( int i = 0; i < 128; i ++ ){
    unsigned char bit = '0';
    for ( int j = 0; j < 7; j ++ ){
     
      if (transformTable[i][j] >= 0 ){
	int bit2 = ((stateString[transformTable[i][j]]) - '0');
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

std::tuple< std::bitset<64>, std::bitset<64> >
Serpent::inverseLinearTransform(std::tuple< std::bitset<64>, std::bitset<64> > state){

  std::string stateString0 = std::get<0>(state).to_string();
  std::string stateString1 = std::get<1>(state).to_string();
  std::string stateString = stateString0.append(stateString1);
  
  std::string tempState = "";
  
  for ( int i = 0; i < 128; i ++ ){
    unsigned char bit = '0';
    for ( int j = 0; j < 7; j ++ ){
     
      if (inverseTransformTable[i][j] >= 0 ){
	int bit2 = ((stateString[inverseTransformTable[i][j]]) - '0');
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
  
  std::cout << "k0 - k3 new method" << std::endl;
  std::cout << std::hex << k0 << std::endl;
  std::cout << std::hex << k1 << std::endl;
  std::cout << std::hex << k2 << std::endl;
  std::cout << std::hex << k3 << std::endl;
  
  
  //Let's try again...
  //4294967295 is the decimal representation of 32 bits of 1's
  //Using this as a mask 
  words[0] = std::bitset<32>(bitMirrorInt(k3 & (unsigned long int)4294967295));
  words[1] = std::bitset<32>(bitMirrorInt(k3 >> 32));
  words[2] = std::bitset<32>(bitMirrorInt(k2 & (unsigned long int)4294967295));
  words[3] = std::bitset<32>(bitMirrorInt(k2 >> 32));
  words[4] = std::bitset<32>(bitMirrorInt(k1 & (unsigned long int)4294967295));
  words[5] = std::bitset<32>(bitMirrorInt(k1 >> 32));
  words[6] = std::bitset<32>(bitMirrorInt(k0 & (unsigned long int)4294967295));
  words[7] = std::bitset<32>(bitMirrorInt(k0 >> 32));
  
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
		^ std::bitset<32>(bitMirrorInt(i-8)) 
		^ std::bitset<32>(bitMirrorInt(phi)));
   
    words[i] = ((words[i] >> 11) | (words[i] << 21));
  }

  std::string preKeys[132];
  for ( int i = 0; i<33; i++ ){
 
    for ( int k = 0; k < 32; k++ ){

      unsigned int sBoxInput = fourBitsFromWords(words[4*i + 8], 
						 words[4*i + 9],
						 words[4*i + 10], 
						 words[4*i + 11], k);
  
      std::string input = std::bitset<4>(sBoxInput).to_string() ;
     
      std::string result = S((35-i) % 8, input);
                 
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
      result.append("1");
    else
      result.append("0");
      
    num >>= 1;
  }
    
  if (result.length() < length)
    result.append(length - result.length(), '0');
 
  
  return result;
}
  
std::string Serpent::S(int box, std::string input){
  return sBoxBitstring[box%8][input];
}

unsigned int Serpent::SInt ( int box, unsigned int input ){
  return sBoxDecimalTable[box % 8][input];
}

//Passes the state through the given sbox
std::tuple< std::bitset<64>, std::bitset<64> > 
Serpent::SBitset ( int box, std::tuple< std::bitset<64>, std::bitset<64> > bitState ){
  
  std::string sBoxString0 = std::get<0>(bitState).to_string();
  std::string sBoxString1 = std::get<1>(bitState).to_string();
  std::string sBoxString = sBoxString0.append(sBoxString1);
  sBoxString = SHat( box, sBoxString );
  
  std::get<0>(bitState) = std::bitset<64>(sBoxString.substr(0, 64));
  std::get<1>(bitState) = std::bitset<64>(sBoxString.substr(64,64));
  return bitState;
}
  
//Passes a binary string of length 4 through the given sbox
std::string Serpent::SInverse(int box, std::string output){
  return sBoxBitstringInverse[box%8][output];
}


//Passes the state through the inverse of the given sbox  
 std::tuple < std::bitset<64>, std::bitset<64> >
 Serpent::inverseSBitset( int box, std::tuple< std::bitset<64>, 
					       std::bitset<64> >  bitState){

  std::string sBoxString0 = std::get<0>(bitState).to_string();
  std::string sBoxString1 = std::get<1>(bitState).to_string();
  std::string sBoxString = sBoxString0.append(sBoxString1);
  sBoxString = SHatInverse( box, sBoxString );
  
  std::get<0>(bitState) = std::bitset<64>(sBoxString.substr(0, 64));
  std::get<1>(bitState) = std::bitset<64>(sBoxString.substr(64,64));
  return bitState;
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


//Flips the bits of the given string, about the 16th bit
//For example, 1 -> 80000000 (in hex)
std::string Serpent::bitMirrorString( std::string image, 
			      std::string reflection ){
  
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

unsigned char Serpent::bitMirrorByte( unsigned char image) {

  unsigned int imageInt = static_cast<unsigned int>(image);
  imageInt = (imageInt & 0xaa) >> 1 | (imageInt & 0x55) << 1;
  imageInt = (imageInt & 0xcc) >> 2 | (imageInt & 0x33) << 2;
  imageInt = (imageInt & 0xf0) >> 4 | (imageInt & 0x0f) << 4;

  unsigned char mirrored = static_cast<unsigned char>(imageInt);

/*std::cout << "image before flip: " << imageInt << std::endl;
  imageInt = bitMirrorInt(imageInt);
  std::cout << "image after flip: " << imageInt << std::endl;
  unsigned char mirrored = static_cast<unsigned char>(imageInt);
  */
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



//Returns the int value of four bits from word, beginning at the specified
// position 
unsigned int Serpent::fourBits( std::bitset<32> word, int pos ){

  unsigned int intVal = (unsigned int)((word.to_ulong() >> (28 - pos)) & 15);
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

// Returns a binary string of four bits from words starting at pos
std::string Serpent::fourBitsString( std::bitset<64> word, int pos ){

  std::bitset<4> bitsFromWords;
  bitsFromWords[3] = word[63-pos];
  bitsFromWords[2] = word[62-pos];
  bitsFromWords[1] = word[61-pos];
  bitsFromWords[0] = word[60-pos];

  return (bitsFromWords.to_string());

}

// Returns a hex string representation of the state
std::string Serpent::hexString (std::tuple< std::bitset<64>, std::bitset<64> > string){

  std::string hexVal0 = "";
  std::string hexVal1 = "";
  std::string hexVal2 = "";
  std::string hexVal3 = "";

  std::bitset<32> bits0 (std::get<0>(string).to_string().substr(0,32));
  std::bitset<32> bits1 (std::get<0>(string).to_string().substr(32,32));
  std::bitset<32> bits2 (std::get<1>(string).to_string().substr(0,32));
  std::bitset<32> bits3 (std::get<1>(string).to_string().substr(32,32));

  for (int i = 0; i < 8; i++ ){
    
    int index = (int)fourBits( bits0, 4*i ); 
    hexVal0.append(1, hexTable[index]);
    
    index = (int)fourBits( bits1, 4*i ); 
    hexVal1.append(1, hexTable[index]);

    index = (int)fourBits( bits2, 4*i ); 
    hexVal2.append(1, hexTable[index]);

    index = (int)fourBits( bits3, 4*i ); 
    hexVal3.append(1, hexTable[index]);

  }
  return hexVal0.append(hexVal1.append(hexVal2.append(hexVal3)));
}

//Nessify output hexstring so that is reads sensibly    
std::string Serpent::nessify (std::string reformat){

  std::string nessied = "";
  for ( int i = 0; i < reformat.length(); i+=2 ){
    
    nessied = nessied.insert(0, 1, reformat[i+1]);
    nessied = nessied.insert(0, 1, reformat[i]);
    
  } 
  return nessied;
}


std::string Serpent::unnessify (std::string reformat){

  std::string unnessied = "";
  for (int i = 0; i < reformat.length(); i+=2 ){
          
  }
}


//Prints the current state in big-endian hex
void Serpent::printState 
(std::tuple< std::bitset<64>, std::bitset<64> > string){

  std::tuple< std::bitset<64>, std::bitset<64> > toPrint 
    = bitMirrorTuple(string);

  std::cout << hexString(toPrint) << std::endl;

}

//Print the current state
void Serpent::printStateBinary (std::tuple< std::bitset<64>, std::bitset<64> > string){

  std::tuple< std::bitset<64>, std::bitset<64> > toPrint
    = bitMirrorTuple(string);

  std::cout << std::get<0>(toPrint) << std::get<1>(toPrint) << std::endl;

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


//Inverse initial permutation
std::tuple< std::bitset<64>, std::bitset<64> >
Serpent::inverseIP ( std::tuple< std::bitset<64>, 
				     std::bitset<64> > state ){

  std::string stateString = std::get<0>(state)
    .to_string().append(std::get<1>(state).to_string());
				
  std::string tempString(128, '0');
				   
  for ( int i = 0; i < 128; i++ ){
    tempString[ip[i]] = stateString[i];
  }
  
  std::get<0>(state) = std::bitset<64>(tempString.substr(0,64));
  std::get<1>(state) = std::bitset<64>(tempString.substr(64,64));
    
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


//Inverse final permutation   					
std::tuple< std::bitset<64>, std::bitset<64> >
Serpent::inverseFP ( std::tuple< std::bitset<64>, std::bitset<64> > state ){

  std::string stateString = std::get<0>(state)
    .to_string().append(std::get<1>(state).to_string());
  
  std::string tempString(128, '0');
  
  for ( int i = 0; i < 128; i++ ){
    tempString[fp[i]] = stateString[i];
  }
  
  std::get<0>(state) = std::bitset<64>(tempString.substr(0,64));
  std::get<1>(state) = std::bitset<64>(tempString.substr(64,64));
    
  return state;  
}

//Encrypt text
void Serpent::encrypt( unsigned char * text ){

  for( int i = 0; i <= 15; i++ ){
    //    std::cout << "text at " << i << ": " 
    //<< static_cast<unsigned int>(text[i]) << std::endl;
    //std::cout << "BitMirrorByte of text: " 
    //	      << static_cast<unsigned int>(bitMirrorByte(text[i])) << std::endl;
    text[i] = bitMirrorByte(text[i]);

  }

  //  text = tempText;

  unsigned long long int stateMSB = readIn(text);
  unsigned long long int stateLSB = readIn(text + 8);
    
  
  
  std::tuple< std::bitset<64>, std::bitset<64> > state;
  std::get<0>(state) = stateMSB;
  std::get<1>(state) = stateLSB;
  std::tuple< std::bitset<64>, std::bitset<64> > tempState;

  std::cout << "State before any changes: " << std::endl;
  printState(state);
  state = initialP(state);

  std::cout << "After IP: " << std::endl;
  printState(state);

  for ( int round = 0; round < 31; round ++ ){
    
    std::get<0>(state) = (std::get<0>(subKeys[round]) ^ std::get<0>(state));
    std::get<1>(state) = (std::get<1>(subKeys[round]) ^ std::get<1>(state));
   
    //std::cout << "Subkey at round " << std::dec << round << ": " << std::endl;
    printState(subKeys[round]);
   
    //std::cout << "After xor " << std::dec << round << ": " << std::endl;
    
    printState(state);

    state = SBitset( round, state);
    //std::cout << "After sbox " << std::endl;
    printState(state);

    state = linearTransform(state);
    // std::cout << "After LT round " << std::dec << round << ": " << std::endl;
    printState(state);
  }
  
    
  std::get<0>(state) = (std::get<0>(subKeys[31]) ^ std::get<0>(state));
  std::get<1>(state) = (std::get<1>(subKeys[31]) ^ std::get<1>(state));
  
  state = SBitset( 7, state);
  
  std::get<0>(state) = (std::get<0>(subKeys[32]) ^ std::get<0>(state));
  std::get<1>(state) = (std::get<1>(subKeys[32]) ^ std::get<1>(state));

  state = finalP(state);
  printState(state);
  printStateBinary(state);
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

  std::cout << "Initial State: " ;
  printState(state);

  state = inverseFP(state);
  std::cout << "After IFP: " ;
  printState(state);

  std::get<0>(state) = (std::get<0>(subKeys[32]) ^ std::get<0>(state));
  std::get<1>(state) = (std::get<1>(subKeys[32]) ^ std::get<1>(state));

  state = inverseSBitset(7, state);
  std::cout << "After inverse s: ";
  printState(state);

  std::get<0>(state) = (std::get<0>(subKeys[31]) ^ std::get<0>(state));
  std::get<1>(state) = (std::get<1>(subKeys[31]) ^ std::get<1>(state));
  
  std::cout << "after xor: ";
  printState(state);

  for ( int round = 30; round >= 0; round -- ){

    state = inverseLinearTransform(state);
    std::cout << "LT: " ;
    printState(state);
   
    state = inverseSBitset(round, state);
    std::cout << "inverse s: ";
    printState(state);

    std::get<0>(state) = (std::get<0>(subKeys[round]) ^ std::get<0>(state));
    std::get<1>(state) = (std::get<1>(subKeys[round]) ^ std::get<1>(state));
    std::cout << "xor: " ;
    printState(state);
  }
    
  state = inverseIP(state);
  std::cout << "after IP: ";
  printState(state);

  std::string nessieOutput = nessify(hexString(bitMirrorTuple(state)));
  std::cout << "Plaintext: " << nessieOutput << std::endl;

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
			    0x00, 0x00, 0x00, 0x00,
			    0x00, 0x00, 0x00, 0x00, 
			    0x00, 0x00, 0x00, 0x00};

 //			    0x00, 0x00, 0x00, 0x00, 
 //			    0x00, 0x00, 0x00, 0x00};

 unsigned char plaintext[16] = 
   {0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00};

 //unsigned char ciphertext[16] =

   

 std::bitset<64> test0 (serpent.readIn(testKey));
 std::bitset<64> test1 (serpent.readIn(testKey + 8));
 std::tuple< std::bitset<64>, std::bitset<64> > testTuple (test0, test1);

 
 serpent.setKeySize(sizeof(testKey)/sizeof(*testKey));
 serpent.setKey(testKey);
 serpent.generateSubKeys();
 serpent.encrypt(plaintext);
 // serpent.decrypt(ciphertext);

 return 0;
}



