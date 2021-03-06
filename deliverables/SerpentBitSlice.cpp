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
 
  const char * hexTable;             //a string used for converting to hex
  std::string dec2bin[16];        //a lookup table for binary strings from ints

  //a lookup table for ints from binary strings
  std::map<std::string, int> bin2dec;     


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
  
  //  int sBoxDecimalTable[8][16];

  //The 8 sboxes used for encryption
  int sBoxes[8][16];

  //The 8 inverse sboxes used for decryption
  int inverseSBoxes[8][16];

  //transform positions indicates what values should be xored together
  //during the linear transformation. 
  //to determine the 0th bit of output, xor the values listed in 
  //transformPositions[0] and so forth.
  //if fewer than 7 values are to be xor'ed, the array is padded out with -1's
  //  int transformPositions[128][7];

  //the inverse of transformPositions. used for decryption
  //int inverseTransformPositions[128][7];
  
 
  //std::map<std::string, std::string> sBoxBitstringInverse[8];
  
public:                    // begin public section
  
  Serpent();

  //Linear transform function to be used only in bitslice mode  
  std::tuple< std::bitset<64>, std::bitset<64> >
  linearTransformBitslice(std::tuple< std::bitset<64>, std::bitset<64> > state);


  //Inverse bitslice linear transform
  std::tuple< std::bitset<64>, std::bitset<64> >
  inverseLinearTransformBitslice(std::tuple< std::bitset<64>, 
					     std::bitset<64> > state);

  //The regular linear transformation that takes place in rounds 0-30
  //std::tuple< std::bitset<64>, std::bitset<64> >
  //linearTransform(std::tuple< std::bitset<64>, std::bitset<64> > state);

  //The inverse of the linear transformation. Used for decryption
  //std::tuple< std::bitset<64>, std::bitset<64> >
  //inverseLinearTransform(std::tuple< std::bitset<64>, std::bitset<64> > state);

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

  void setKeySize( int keyLength);

  int keySize();

  int blockSize();

    unsigned int SInt(int box, unsigned int input);

  std::tuple< std::bitset<64>, std::bitset<64> > 
  SBitset( int box,  std::tuple< std::bitset<64>, std::bitset<64> > state );

    //Passes the state through the sbox in bitslice mode
 std::tuple < std::bitset<64>, std::bitset<64> >
 SboxBitslice ( int box,  std::tuple< std::bitset<64>, 
				      std::bitset<64> >  state);

  //Passes the state through the inverse sbox in bitslice mode
  std::tuple < std::bitset<64>, std::bitset<64> >
  inverseSboxBitslice ( int box, std::tuple < std::bitset<64>, 
					    std::bitset<64> > state);

    std::string bitMirrorString (std::string image, std::string reflection);

  unsigned int bitMirrorInt ( unsigned int image );

  unsigned char bitMirrorByte( unsigned char image);

  std::bitset<32> bitMirrorBitset ( std::bitset<32> image );

  std::tuple< std::bitset<64>, std::bitset<64> > 
  bitMirrorTuple ( std::tuple< std::bitset<64>, std::bitset<64> > image );

  unsigned int fourBits 
  ( std::tuple< std::bitset<64>, std::bitset<64> > state, int pos );

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

  //Encrypt the given plaintext
  void encrypt( unsigned char * text );

  //Decrypt the given ciphertext
  void decrypt ( unsigned char * text );
  
};


//class Serpent {

Serpent::Serpent() { 
  
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

  //An array for looking up binary string representation of 4-bit ints
  std::string tdec2bin[16] = {"0000", "0001", "0010", "0011", 
			      "0100", "0101", "0110", "0111", 
			      "1000", "1001", "1010", "1011", 
			      "1100", "1101", "1110", "1111"};

  std::copy(tdec2bin, tdec2bin+16, dec2bin);  
  
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
}


//Bitslice linear transformation
std::tuple< std::bitset<64>, std::bitset<64> > Serpent::linearTransformBitslice 
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


//Inverse linear transformation in bitslice mode 
 std::tuple< std::bitset<64>, std::bitset<64> >
 Serpent::inverseLinearTransformBitslice(std::tuple< std::bitset<64>, 
						     std::bitset<64> > state){
 
 std::string temp0 = std::get<0>(state).to_string();
  std::string temp1 = std::get<1>(state).to_string();
  
  std::bitset<32> x0 (temp0.substr(0, 32));
  std::bitset<32> x1 (temp0.substr(32, 32));
  std::bitset<32> x2 (temp1.substr(0, 32));
  std::bitset<32> x3 (temp1.substr(32, 32));

  rotate(x2, 10);
  rotate(x0, 27);
  x2 = x2^x3^(x1 >> 7);
  x0 = x0^x1^x3;
  rotate(x3, 25);
  rotate(x1, 31);
  x3 = x3^x2^(x0 >> 3);
  x1 = x0^x1^x2;
  rotate(x2, 29);
  rotate(x0, 19);

  std::get<0>(state) = std::bitset<64>((x0.to_string()).append(x1.to_string()));
  std::get<1>(state) = std::bitset<64>((x2.to_string()).append(x3.to_string()));

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
      // std::string result = bitMirrorString(Bitstring(resultInt, 4), "");

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


//Return the sbox value for the given input and sbox
//For example, if box = 0 and input = 12, SInt returns 8
unsigned int Serpent::SInt ( int box, unsigned int input ){
  return sBoxes[box % 8][input];
}

//Passes the state through the given sbox
std::tuple< std::bitset<64>, std::bitset<64> > 
Serpent::SBitset ( int box, std::tuple< std::bitset<64>, std::bitset<64> > state ){

  int index;
  unsigned long long int lowerState = 0;
  unsigned long long int upperState = 0;

  for( int i = 0; i < 16; i ++ ){
    
    index = fourBits(state, 4*i);
    lowerState ^= ((unsigned long long int)(sBoxes[box%8][index]) << 
		   (60 - (4*i)));
  }

  for( int i = 16; i < 32; i ++ ){

    index = fourBits(state, 4*i);
    upperState ^= ((unsigned long long int)(sBoxes[box%8][index]) << 
		   (60 - (4*i)));
  }

  std::get<0>(state) = std::bitset<64>(lowerState);
  std::get<1>(state) = std::bitset<64>(upperState);
  return state;

}
/*

//Passes the state through the inverse of the given sbox  
std::tuple< std::bitset<64>, std::bitset<64> > 
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
*/
//Passes the state through the sbox in bitslice mode
 std::tuple < std::bitset<64>, std::bitset<64> >
 Serpent::SboxBitslice ( int box,  std::tuple< std::bitset<64>, 
					       std::bitset<64> >  state){
         
   std::string state0 = std::get<0>(state).to_string();
   std::string state1 = std::get<1>(state).to_string();
   
   std::string stateString0 = "";
   std::string stateString1 = "";
   std::string stateString2 = "";
   std::string stateString3 = "";

   int sValue = 0;

   for (int i = 0; i<32; i ++){
     std::string tempString1 = "";
     tempString1.append(1, state0[i]);
     tempString1.append(1, state0[i+32]);
     tempString1.append(1, state1[i]);
     tempString1.append(1, state1[i+32]);
        
     sValue = sBoxes[box%8][bin2dec[tempString1]];
    
     std::string tempString2 = dec2bin[sValue];
    
     stateString0.append(1, tempString2[0]);
     stateString1.append(1, tempString2[1]);
     stateString2.append(1, tempString2[2]);
     stateString3.append(1, tempString2[3]);
   }
   
   stateString0.append(stateString1);
   stateString2.append(stateString3);
   std::get<0>(state) = std::bitset<64>(stateString0);
   std::get<1>(state) = std::bitset<64>(stateString2);
   return state;

}

//Passes the state through the given inverse sbox in bitslice mode
std::tuple < std::bitset<64>, std::bitset<64> >
Serpent::inverseSboxBitslice ( int box, std::tuple < std::bitset<64>, 
					    std::bitset<64> > state){

 std::string state0 = std::get<0>(state).to_string();
   std::string state1 = std::get<1>(state).to_string();
   
   std::string stateString0 = "";
   std::string stateString1 = "";
   std::string stateString2 = "";
   std::string stateString3 = "";

   int sValue = 0;

   for (int i = 0; i<32; i ++){
     std::string tempString1 = "";
     tempString1.append(1, state0[i]);
     tempString1.append(1, state0[i+32]);
     tempString1.append(1, state1[i]);
     tempString1.append(1, state1[i+32]);
        
     sValue = inverseSBoxes[box%8][bin2dec[tempString1]];
    
     std::string tempString2 = dec2bin[sValue];
    
     stateString0.append(1, tempString2[0]);
     stateString1.append(1, tempString2[1]);
     stateString2.append(1, tempString2[2]);
     stateString3.append(1, tempString2[3]);
   }
   
   stateString0.append(stateString1);
   stateString2.append(stateString3);
   std::get<0>(state) = std::bitset<64>(stateString0);
   std::get<1>(state) = std::bitset<64>(stateString2);
   return state;


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

  for (int i = 0; i < 32; i ++ ){
    
    index = (int)(fourBits(state, 4*i));
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


//Encrypt text
void Serpent::encrypt( unsigned char * text ){

  for( int i = 0; i < 16; i++ ){
    text[i] = bitMirrorByte(text[i]);
  }

  unsigned long long int stateMSB = readIn(text);
  unsigned long long int stateLSB = readIn(text + 8);
      
  std::tuple< std::bitset<64>, std::bitset<64> > state;
  std::get<0>(state) = stateMSB;
  std::get<1>(state) = stateLSB;
  std::tuple< std::bitset<64>, std::bitset<64> > tempState;


  // std::cout << "State before any changes: " << std::endl;
  //printState(state);
  //state = initialP(state);
  //std::cout << "After IP: " << std::endl;
  //printState(state);

  for ( int round = 0; round < 31; round ++ ){
    
    std::get<0>(state) = (std::get<0>(subKeys[round]) ^ std::get<0>(state));
    std::get<1>(state) = (std::get<1>(subKeys[round]) ^ std::get<1>(state));
   
    //std::cout << "Subkey at round " << std::dec << round << ": " << std::endl;
    //printState(subKeys[round]);
   
    //std::cout << "After xor " << std::dec << round << ": " << std::endl;
    
    // printState(state);

    state = SboxBitslice( round, state);
    //std::cout << "After sbox " << std::endl;
    //printState(state);

    state = linearTransformBitslice(state);
    //std::cout << "After LT round " << std::dec << round << ": " << std::endl;
    //printState(state);
  }
  
    
  std::get<0>(state) = (std::get<0>(subKeys[31]) ^ std::get<0>(state));
  std::get<1>(state) = (std::get<1>(subKeys[31]) ^ std::get<1>(state));
  
  state = SboxBitslice( 7, state);
  
  std::get<0>(state) = (std::get<0>(subKeys[32]) ^ std::get<0>(state));
  std::get<1>(state) = (std::get<1>(subKeys[32]) ^ std::get<1>(state));

    
  std::string nessieOutput = nessify(hexString(bitMirrorTuple(state)));
  //std::cout << "Ciphertext: " << nessieOutput << std::endl;

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

  //std::cout << "Initial State: " ;
  //printState(state);
 
  std::get<0>(state) = (std::get<0>(subKeys[32]) ^ std::get<0>(state));
  std::get<1>(state) = (std::get<1>(subKeys[32]) ^ std::get<1>(state));

  state = inverseSboxBitslice(7, state);
  //std::cout << "After inverse s: ";
  //printState(state);

  std::get<0>(state) = (std::get<0>(subKeys[31]) ^ std::get<0>(state));
  std::get<1>(state) = (std::get<1>(subKeys[31]) ^ std::get<1>(state));
  
  //std::cout << "after xor: ";
  //printState(state);

  for ( int round = 30; round >= 0; round -- ){

    state = inverseLinearTransformBitslice(state);
    //std::cout << "LT: " ;
    //printState(state);
   
    state = inverseSboxBitslice(round, state);
    //std::cout << "inverse s: ";
    //printState(state);

    std::get<0>(state) = (std::get<0>(subKeys[round]) ^ std::get<0>(state));
    std::get<1>(state) = (std::get<1>(subKeys[round]) ^ std::get<1>(state));
    //std::cout << "xor: " ;
    //printState(state);
  }

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

 unsigned char testKey[] = {0x00, 0x00, 0x00, 0x00, 
			    0x00, 0x00, 0x00, 0x00, 
			    0x00, 0x00, 0x00, 0x00, 
			    0x00, 0x00, 0x00, 0x00};
 //	    0x00, 0x00, 0x00, 0x00, 
 //			    0x00, 0x00, 0x00, 0x00};
 
 //			    0x00, 0x00, 0x00, 0x00, 
 //			    0x00, 0x00, 0x00, 0x00};
 
 unsigned char plaintext[16] = 
   {0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00};
 /*
 unsigned char ciphertext[16] =
   {0x26, 0x4e, 0x54, 0x81, 
    0xef, 0xf4, 0x2a, 0x46, 
    0x06, 0xab, 0xda, 0x06, 
    0xc0, 0xbf, 0xda, 0x3d};
 */

 //Set the keysize to the given keysize (in bytes)
 serpent.setKeySize(sizeof(testKey)/sizeof(*testKey));
 serpent.setKey(testKey);

 
 //Encrypt the given plaintext n times 
 
for (int i = 0; i < n; i++ ){
   serpent.encrypt(plaintext);
 }

 return 0;
}



