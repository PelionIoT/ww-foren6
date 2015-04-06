/*
  Description: aes-128-cbc crypto
  Author: WigWag Inc. 
  Programmer: Yash Goyal
  Version: 1.0
  State: Tested, Working aganist TI hardware 
  Reference:
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include "ww_crypto.h"

#define CRYPTO_DEBUG 0

// foreward sbox
const unsigned char sbox[256] =   {
//0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, //0
0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, //1
0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, //2
0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, //3
0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, //4
0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, //5
0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, //6
0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, //7
0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, //8
0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, //9
0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, //A
0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, //B
0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, //C
0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, //D
0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, //E
0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 }; //F

// inverse sbox
const unsigned char rsbox[256] =
{ 0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb
, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb
, 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e
, 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25
, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92
, 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84
, 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06
, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b
, 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73
, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e
, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b
, 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4
, 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f
, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef
, 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61
, 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d };

// round constant
const unsigned char Rcon[10] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};


// multiply by 2 in the galois field
unsigned char galois_mul2(unsigned char value)
{
  signed char temp;
  // cast to signed value
  temp = (signed char) value;
  // if MSB is 1, then this will signed extend and fill the temp variable with 1's
  temp = temp >> 7;
  // AND with the reduction variable
  temp = temp & 0x1b;
  // finally shift and reduce the value
  return ((value << 1)^temp);
}

// AES encryption and decryption function
// The code was optimized for memory (flash and ram)
// Combining both encryption and decryption resulted in a slower implementation
// but much smaller than the 2 functions separated
// This function only implements AES-128 encryption and decryption (AES-192 and 
// AES-256 are not supported by this code) 
int aes_enc_dec(unsigned char *input, int inlen, unsigned char *aes_key, unsigned char dir, unsigned char *output)
{
  unsigned char buf1, buf2, buf3, buf4, round, i;
  unsigned char state[16];
  unsigned char key[16];

  int iteration = ceil(inlen / 16.0);
  int bytes = 16;

  int rem_bytes = inlen % 16;
  if(rem_bytes == 0)
    rem_bytes = bytes;
  
  int outlen = iteration * 16;
  int cycle = 0;

  //Enter here only while encrypting
  if(!dir) {
    for (i = inlen; i < outlen - 1; ++i){
      input[i] = 0x00;
    }
    input[i] = outlen - inlen;
    if(input[i] == 0) {
      for (i = inlen; i < inlen + 15; ++i) {
        input[i] = 0x00;
      }
      input[i] = 16;
      outlen += 16;
      iteration++;
    }
#if CRYPTO_DEBUG
    printf("Padded number of bytes: %d, last byte: %d\n", outlen - inlen, input[i]);
#endif /* CRYPTO_DEBUG */
  }

#if CRYPTO_DEBUG
for (i = 0; i < outlen; ++i) {
    printf("%x,", input[i]);
  }
  printf("\n");
#endif /* CRYPTO_DEBUG */

  if(dir) {
    if(inlen % 16 != 0) {
      printf("\n**********DROPPING THE PACKET NOT THE MULTIPLE OF 16****************\n");
      return 0;
    }
  }

#if CRYPTO_DEBUG
  printf("Number of encryption iteration: %d\n", iteration);
#endif /* CRYPTO_DEBUG */

  unsigned char *encrypt_out = NULL;
  encrypt_out = (unsigned char*)malloc(sizeof(char) * outlen);

  while(iteration != cycle) {

    memcpy(key, aes_key, 16);
    memset(state, 0, 16);
    // if(cycle != (iteration - 1)){
    //   bytes = 16;
    // }
    // else{
    //   bytes = rem_bytes;
    // }

    memcpy(state, (input + (cycle)*16), 16);

#if CRYPTO_DEBUG
    printf("\t%d Input Data: [", cycle);
    for (i=0;i<15;i++) {
       printf("%x, ", state[i]);
    }
    printf("%x]\n", state[15]);

    printf("\tKey: [");
    for (i=0;i<15;i++) {
       printf("%x, ", key[i]);
    }
    printf("%x]\n", key[15]);
#endif /* CRYPTO_DEBUG */
    // In case of decryption
    if (dir) {
      // compute the last key of encryption before starting the decryption
      for (round = 0 ; round < 10; round++) {
        //key schedule
        key[0] = sbox[key[13]]^key[0]^Rcon[round];
        key[1] = sbox[key[14]]^key[1];
        key[2] = sbox[key[15]]^key[2];
        key[3] = sbox[key[12]]^key[3];
        for (i=4; i<16; i++) {
          key[i] = key[i] ^ key[i-4];
        }
      }
      
      //first Addroundkey
      for (i = 0; i <16; i++){
        state[i]=state[i] ^ key[i];
      }
    }

    
    // main loop
    for (round = 0; round < 10; round++){
      if (dir){
        //Inverse key schedule
        for (i=15; i>3; --i) {
    key[i] = key[i] ^ key[i-4];
        }  
        key[0] = sbox[key[13]]^key[0]^Rcon[9-round];
        key[1] = sbox[key[14]]^key[1];
        key[2] = sbox[key[15]]^key[2];
        key[3] = sbox[key[12]]^key[3]; 
      } else {
        for (i = 0; i <16; i++){
          // with shiftrow i+5 mod 16
    state[i]=sbox[state[i] ^ key[i]];
        }
        //shift rows
        buf1 = state[1];
        state[1] = state[5];
        state[5] = state[9];
        state[9] = state[13];
        state[13] = buf1;

        buf1 = state[2];
        buf2 = state[6];
        state[2] = state[10];
        state[6] = state[14];
        state[10] = buf1;
        state[14] = buf2;

        buf1 = state[15];
        state[15] = state[11];
        state[11] = state[7];
        state[7] = state[3];
        state[3] = buf1;
      }
      //mixcol - inv mix
      if ((round > 0 && dir) || (round < 9 && !dir)) {
        for (i=0; i <4; i++){
          buf4 = (i << 2);
          if (dir){
            // precompute for decryption
            buf1 = galois_mul2(galois_mul2(state[buf4]^state[buf4+2]));
            buf2 = galois_mul2(galois_mul2(state[buf4+1]^state[buf4+3]));
            state[buf4] ^= buf1; state[buf4+1] ^= buf2; state[buf4+2] ^= buf1; state[buf4+3] ^= buf2; 
          }
          // in all cases
          buf1 = state[buf4] ^ state[buf4+1] ^ state[buf4+2] ^ state[buf4+3];
          buf2 = state[buf4];
          buf3 = state[buf4]^state[buf4+1]; buf3=galois_mul2(buf3); state[buf4] = state[buf4] ^ buf3 ^ buf1;
          buf3 = state[buf4+1]^state[buf4+2]; buf3=galois_mul2(buf3); state[buf4+1] = state[buf4+1] ^ buf3 ^ buf1;
          buf3 = state[buf4+2]^state[buf4+3]; buf3=galois_mul2(buf3); state[buf4+2] = state[buf4+2] ^ buf3 ^ buf1;
          buf3 = state[buf4+3]^buf2;     buf3=galois_mul2(buf3); state[buf4+3] = state[buf4+3] ^ buf3 ^ buf1;
        }
      }
      
      if (dir) {
        //Inv shift rows
        // Row 1
        buf1 = state[13];
        state[13] = state[9];
        state[9] = state[5];
        state[5] = state[1];
        state[1] = buf1;
        //Row 2
        buf1 = state[10];
        buf2 = state[14];
        state[10] = state[2];
        state[14] = state[6];
        state[2] = buf1;
        state[6] = buf2;
        //Row 3
        buf1 = state[3];
        state[3] = state[7];
        state[7] = state[11];
        state[11] = state[15];
        state[15] = buf1;         
             
        for (i = 0; i <16; i++){
          // with shiftrow i+5 mod 16
          state[i]=rsbox[state[i]] ^ key[i];
        } 
      } else {
        //key schedule
        key[0] = sbox[key[13]]^key[0]^Rcon[round];
        key[1] = sbox[key[14]]^key[1];
        key[2] = sbox[key[15]]^key[2];
        key[3] = sbox[key[12]]^key[3];
        for (i=4; i<16; i++) {
          key[i] = key[i] ^ key[i-4];
        }
      }
    }
    if (!dir) {
    //last Addroundkey
      for (i = 0; i <16; i++){
        // with shiftrow i+5 mod 16
        state[i]=state[i] ^ key[i];
      } // enf for
    } // end if (!dir)

    //printf("HERE");
    memcpy((output + (cycle)*16), state, 16);

#if CRYPTO_DEBUG
    printf("\tCrypted: [");
    for (i=(cycle*16);i<(cycle*16 + 15);i++) {
       printf("%x, ", output[i]);
    }
    printf("%x]\n", output[(cycle*16 + 15)]);
#endif /* CRYPTO_DEBUG */


    cycle++;
  }
  free(encrypt_out);
  //output = encrypt_out;
  if(dir) {
    outlen = outlen - output[inlen - 1];
  } else {
    if(outlen % 16 != 0) {
      return 0;
    }
  }
  return outlen;
} // end function

int add(int a, int b) {
  return a + b;
}

void add_string (char *a, char *b, char *c) {
  //char *c;
  //c = (char*)malloc(sizeof(char) * 50);
  memset(c, 0, 50);
  strcat(c, a);
  strcat(c, b);
//  strcat(a, b);
//  printf("Concat string a: %s\n", a);
  
  //return c;
}

//int main(void) {
//  char src[5] = "abc";
//  char dest[5] = "123";
//  char *result;
//  result = (char*)malloc(sizeof(char) * 15);
//  add_string(src, dest, result);
//  printf("%s\n", result); 
//  return 0;
//}

int main( void )
{
  unsigned char state[] = {0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x68, 0x65, 0x6c,  
                               0x6c, 0x6f, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x68};
  unsigned char key1[]   = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  unsigned char key2[]   = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  unsigned char i;
   
  unsigned char output[50];


  //aes_enc_dec(state,key1,0,output);
  
#if CRYPTO_DEBUG
  printf("Encrypted Data: ");
  for (i=0;i<15;i++) {
     printf("%x, ", output[i]);
  }
  printf("%x\n", output[15]);
#endif /* CRYPTO_DEBUG */


  //aes_enc_dec(state,key2,1, output);
  
#if CRYPTO_DEBUG
  printf("Decrypted Data: ");
  for (i=0;i<15;i++) {
     printf("%x, ", output[i]);
  }
  printf("%x  \n", output[15]);
#endif /* CRYPTO_DEBUG */
  
  return 0;
}