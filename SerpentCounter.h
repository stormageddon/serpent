#ifndef SERPENTCOUNTER_H
#define SERPENTCOUNTER_H

class Serpent
{
  
  
private:

    
  int ip[128];                       //initial permutation
  int fp[128];                       //final permutation
  const char * hexTable;             //a string used for converting to hex

  //a lookup for the binary representation of an int 0<=i<=15
  std::string dec2bin[16];           
  int size;                          //size of the key


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

#endif
