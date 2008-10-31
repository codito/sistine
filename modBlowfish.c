/*============================================================

Modified Blowfish Encryption Utility
By Liet-Kynes

See blowfish.c for more information

============================================================*/




#include <stdio.h>
#include "blowfish.h"


int main(int argc, char** argv) {

  if(argc!=3) {
    printf("Usage: modBlowfish plaintext key");
    return 1;
  } else {
    printf((char*)encryptString(argv[1],argv[2]));
  }

  return 0;

}
