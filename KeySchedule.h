#ifndef KEYSCHEDULE_H
#define KEYSCHEDULE_H

class KeySchedule{
 
public:
  KeySchedule();

  void setKey (unsigned char user_key[]); //Sets the key (128, 192, 256 bits)

  int keySize (); //returns the size of the encryption key
 
  static int ip[64];
  int key_size;
  unsigned long long int k0, k1, k2, k3;

};


#endif
