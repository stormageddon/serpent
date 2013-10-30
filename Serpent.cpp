#include <stdio.h>
#include <iostream>
#include <bitset>


class Serpent
{
  public:                    // begin public section
    Serpent();
  void linearTransform(std::bitset<32> x0, std::bitset<32> x1, std::bitset<32> x2, std::bitset<32> x3);

  void shiftRight(unsigned char *ar, int size, int shift);

  void shiftLeft(unsigned char *array);

  void rotate(std::bitset<32> &b, unsigned m);
};

//class Serpent {

Serpent::Serpent() { }

void Serpent::linearTransform(std::bitset<32> x0, std::bitset<32> x1, std::bitset<32> x2, std::bitset<32> x3) {
  std::cout << x0 << std::endl;
  std::cout << x1 << std::endl;
  std::cout << x2 << std::endl;
  std::cout << x3 << std::endl;
  rotate(x0,13);
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
  std::cout << x0 << std::endl;
  std::cout << x1 << std::endl;
  std::cout << x2 << std::endl;
  std::cout << x3 << std::endl;
    //b <<= 4;
    //rotate(b,4);
    //std::cout << b << std::endl;

}

// Rotates to the left
void Serpent::rotate(std::bitset<32> &b, unsigned m) {
  b = b << m | b >> (32-m);
}

//}
int main( )
{
  Serpent::Serpent serpent; 
  std::bitset<32> x0 (std::string("11000000000000000000000000000110"));
  std::bitset<32> x1 (std::string("11000000000000000000000000000110"));
  std::bitset<32> x2 (std::string("11000000000000000000000000000110"));
  std::bitset<32> x3 (std::string("11000000000000000000000000000110"));
  serpent.linearTransform(x0,x1,x2,x3); 
  return 0;
}



