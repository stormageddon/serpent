#include <iostream>
#include <iomanip>
#include <bitset>
#include <string>
#include <cstring>
#include <tuple>
#include <map>
#include <sstream>
#include <fstream>
#include "SerpentOptimizedFinal.h"
#include "SerpentStream.h"


//Uses the Serpent cipher to encrypt the contents of a file
//using CTR Mode

SerpentStream::SerpentStream(){

  //set a default keyStream of all 0's
  unsigned char tKeyStream[16] = {0x00, 0x00, 0x00, 0x00, 
				  0x00, 0x00, 0x00, 0x00, 
				  0x00, 0x00, 0x00, 0x00, 
				  0x00, 0x00, 0x00, 0x00};

  std::copy(tKeyStream, tKeyStream+16, keyStream);

  //initialize the counter for the number of blocks
  blockCounter = 0;

  //initialize the counter for bytes in a block
  byteCounter = 0;

  //initialize the default nonce
  nonce = 0;
}

//Return the stream cipher's key size in bytes
int SerpentStream::keySize(){
  return 16;
}


//Sets the nonce for the stream cipher
//Nonce must be a 64 bit number
void SerpentStream::setNonce( unsigned long long int nonce ){

   for ( int i = 0; i < 8; i++ ){
    //Store bytes of nonce in the first half of keyStream
     keyStream[i] = (unsigned char)( (nonce >> (56 - (8*i))) & 255);
   }
   
}



//Sets the key for the given stream cipher
void SerpentStream::setKey(unsigned char * key){
  serpent.setKeySize(16);
  serpent.setKey(key);
}


//Encrypt the next byte
int SerpentStream::encrypt(int byte ){

  //If we've reached the end of the keyStream block
  if (byteCounter % 16 == 0){
    
   
    //The initialization vector stays the same, so leave it be
    //Enter the updated blockCounter into latter half
    //of the keyStream array in preparation for encryption
    for ( int i = 0; i < 8; i++){
      keyStream[i+8] = (unsigned char)((blockCounter >> (56 - 8*i)) & 255);
    }

    //Increment the block counter to generate new plaintext 
    //for the Serpent cipher
    blockCounter ++;
        
    //Encrypt the keyStream
    serpent.encrypt(keyStream);
    
    //Reset the byteCounter to 0
    byteCounter = 0;
  } 
  byteCounter ++;
  return byte ^ (int)keyStream[byteCounter-1];
  
}


int main(int argc, char** argv)
{
  
  std::string usageWarning =  "usage: [-i/--input fileName] [-o/--output fileName] [-k/--key 32bitKey] [-n/--nonce initializationVector]";

  unsigned long long int nonce = 0;
  bool encrypting = true;

  std::string inputFile;
  std::string outputFile;
  std::string key;

  bool hasInputFile = false;
  bool hasOutputFile = false;
  bool hasKey = false;

  std::ofstream out;
  std::streambuf *coutbuf;

  SerpentStream serpentStream;

  unsigned char defaultKey[] = {0x00, 0x00, 0x00, 0x00, 
				0x00, 0x00, 0x00, 0x00, 
				0x00, 0x00, 0x00, 0x00, 
				0x00, 0x00, 0x00, 0x00};
  
  if (argc < 2) {
    std::cerr << usageWarning << std::endl;
    return 1;
  }
  
  //Parse command line input
  for( int i = 1; i < argc; i++ ) {

    //If the nonce is specified
    if (0 == strncmp(argv[i], "-n", 2) || 
	0 == strncmp(argv[i], "--nonce", 7)) {
      i = i + 1;
      nonce = (unsigned long long int)std::stof(argv[i]);
    }
    
    //If the input file is specified
    else if (0 == strncmp(argv[i], "-i", 2) || 
	     0 == strncmp(argv[i], "--input", 7)) {

      i = i + 1;
      inputFile = argv[i];
      hasInputFile = true;
    }

    //If the output file is specified
    else if (0 == strncmp(argv[i], "-o", 2) || 
	     0 == strncmp(argv[i], "--output", 8)) {
      i = i + 1;
      outputFile = argv[i];
      out.open(outputFile);
      coutbuf = std::cout.rdbuf(); //save old buf
      std::cout.rdbuf(out.rdbuf()); 
      hasOutputFile = true;
    }

    //If the encryption key is specified
    else if (0 == strncmp(argv[i], "-k", 2) || 
	     0 == strncmp(argv[i], "--key", 5)) {
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
  
  if(hasKey){
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
    memcpy(defaultKey, new_key, sizeof(defaultKey));
  }
  
  //Set the key to use for file encryption
  serpentStream.setKey(defaultKey);
  
   
  //Set the nonce
  serpentStream.setNonce(nonce);

   std::ifstream in(inputFile);

   unsigned char  x;
  std::string temp_string = "";

  //encrypt the file byte by byte
  while (in >> std::noskipws >> x) {
    int cipherByte = serpentStream.encrypt((int)x);
    std::cout << (char)cipherByte;
  }
  
  //Restore the old buffer
  std::cout.rdbuf(coutbuf);
  
  //Close the output file
  if (hasOutputFile){
    out.close();
  }
  
  //Close the input file
  if (hasInputFile){
    in.close();
  }
  
  return 0;
}
