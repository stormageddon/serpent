#define USE_NONOPTIMIZED_SERPENT

#ifdef USE_OPTIMIZED_SERPENT
#include "SerpentOptimizedFinal.h"
#endif

#ifdef USE_NONOPTIMIZED_SERPENT
#include "Serpent.h"
#endif

#ifndef SERPENTSTREAM_H
#define SERPENTSTREAM_H



class SerpentStream{

  Serpent serpent;
  unsigned char keyStream[16];
  
  //Counter to be incremented for each plaintext block to 
  //be encrypted
  //Must be block size - nonce size = 64 bits
  unsigned long long int blockCounter;
  
  
  //Counter to be incremented each time a new bit is encrypted
  //indicates when a new keystream block needs to be generated
  int byteCounter;;
  
  
  //Initialization vector supplied by the user
  //must be a 64 bit integer
  unsigned long long int nonce;
  
  
 public:
  
  SerpentStream();
  
  //Returns this stream cipher's key size in bytes. 
  //Returns 16
  int keySize();
  
  
  //Sets the nonce for the stream cipher
  //Nonce must be a 64 bit number
  void setNonce( unsigned long long int nonce );
  
  //Sets the key for this stream cipher
  void setKey(unsigned char * key);
  
  
  //Encrypts the next byte
  int encrypt(int byte);
  
  
};

#endif
