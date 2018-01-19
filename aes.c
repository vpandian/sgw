#include <stdio.h>
#include <string.h>
#include <iostream>
#include <stdint.h>
#include <iomanip>
using namespace std;

#define Nb 4
#define Nr 10
#define Nk 4

uint8_t sBox[256] = {
  //0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

class aes 
{
protected:
  void subBytes(uint8_t state[4][Nb]);
  void shiftRows(uint8_t state[4][Nb]);
  void mixColumns(uint8_t state[4][Nb]);
  void addRoundKey(uint8_t state[4][Nb], uint32_t w[Nb]);
  
public:
  void cipher(uint8_t * in, uint8_t * out, uint32_t w[Nb*(Nr +1)]);
//void invCipher(uint8_t in[4*Nb], uint8_t out[4*Nb], uint32_t w[Nb*(Nr +1)]);
};

class aes_128_cbc : public aes
{
public:
void AES128_CBC_encrypt_buffer(uint8_t *P, uint8_t *C,uint32_t L,uint8_t *K, uint8_t *IV);
};

void addRoundKey(uint8_t state[4][Nb], uint32_t w[Nb])
{
  for(int c = 0; c < Nb; c++)
    {
      uint32_t s = ((state[0][c] << 24) | (state[1][c] << 16) | (state[2][c] << 8) | (state[3][c] << 0)) ^ w[c];
      state[0][c] = (s >> 24) & 0xFF;
      state[1][c] = (s >> 16) & 0xFF;
      state[2][c] = (s >> 8) & 0xFF;
      state[3][c] = (s >> 0) & 0xFF;
    }  

}

void subBytes(uint8_t state[4][Nb])
{
  for(int r = 0; r < 4 ; r++)
    {
      for(int c = 0; c < Nb; c++)
	{
	  state[r][c] = sBox[state[r][c]];
	}

    }

}

void shiftRows(uint8_t state[4][Nb])
{
  for(int r = 1; r < 4 ; r++)
    {
      uint8_t temp[4];
      // Now store the values in a temp variable.
      // For the 0th row store nothing
      // For the 1st row store 1 variable
      // For the 2nd row store 2 variables
      // For the 3rd row store 3 variables
      for(int t = 0;t < r;t++)
	{
	  temp[t] = state[r][t];
	}
      for(int c = r; c < Nb; c++)
	{
	  // shift.. t is row. for 1st row.. t = 1. so it will shift 1 to the left
	  state[r][(c-r)] = state[r][c];
	}
      // put the temp values to the remaining elements in the matrix
      for(int t = 0;t < r;t++)
	{
	  state[r][Nb-r+t] = temp[t];
	}
    }  
}


uint8_t x_times_x(uint8_t x)
{
  return ((x << 1) ^ ((x & 0x80) ? 0x1b: 0x00));
}

void mixColumns(uint8_t state[4][Nb])
{

  for(int c =0; c < Nb; c++)
    {
      state[0][c] = (x_times_x(state[0][c]) ^
		     (x_times_x(state[1][c]) ^ state[1][c]) ^
		     state[2][c] ^
		     state[3][c]);

      state[1][c] = (state[0][c] ^
		     x_times_x(state[1][c]) ^
		     (x_times_x(state[2][c]) ^ state[2][c]) ^
		     state[3][c]);

      state[2][c] = (state[0][c] ^
		     state[1][c] ^
		     x_times_x(state[2][c]) ^
		     (x_times_x(state[3][c]) ^ state[3][c]));

      state[3][c] = ((x_times_x(state[0][c]) ^ state[0][c]) ^
		     state[1][c] ^
		     x_times_x(state[2][c]) ^
		     x_times_x(state[3][c]));
    }

}
void cipher(uint8_t * in, uint8_t * out, uint32_t w[Nb*(Nr +1)])
{
  uint8_t state[4][Nb];



//state = in;
  for(int i = 0; i < 4;i++)
  {
    for (int j = 0; j < Nb; j++)
    {
      state[i][j] = in[i*Nb+j];
    }
  }
  
  addRoundKey(state,&w[0]);
  for(int round = 1; round < Nr;round++)
    {
      subBytes(state);
      shiftRows(state);
      mixColumns(state);
      addRoundKey(state,&w[round*Nb]);
    }
  subBytes(state);
  shiftRows(state);
  addRoundKey(state,&w[Nr*Nb]);
  
//out = state;

  for(int i = 0; i < 4;i++)
  {
    for (int j = 0; j < Nb; j++)
    {
      out[i*Nb+j] = state[i][j];
    }
  }
  
}

uint32_t rCon[10] = {
  0x01000000,
  0x02000000,
  0x04000000,
  0x08000000,
  0x10000000,
  0x20000000,
  0x40000000,
  0x80000000,
  0x1b000000,
  0x36000000
};

uint32_t subWord(uint32_t w)
{
  uint8_t b0 = (w >> 24) & 0xFF;
  uint8_t b1 = (w >> 16) & 0xFF;
  uint8_t b2 = (w >> 8) & 0xFF;
  uint8_t b3 = (w >> 0) & 0xFF;
  
  return ((sBox[b0] << 24) | (sBox[b1] << 16) | (sBox[b2] << 8) | (sBox[b3]<< 0));
}

uint32_t rotWord(uint32_t w)
{
  return w << 8 | w >> 24;
}

void keyExpansion(uint8_t * key, uint32_t *w)
{
  int i = 0;
  for(;i<Nk;i++)
    {
      
      w[i]= ((key[4*i] << 24) | (key[4*i+1] << 16) | (key[4*i+2] << 8) | (key[4*i+3]<< 0));
    }
  for(;i<Nb*(Nr+1);i++)
    {
      uint32_t temp = w[i-1];
      if(i%Nk == 0)
	{
	  temp = subWord(rotWord(temp)) ^ rCon[i/Nk];
	}
      w[i] = w[i-Nk] ^ temp;
    }

}
void AES128_CBC_encrypt_buffer(uint8_t *P, uint8_t *C,uint32_t len,uint8_t *K, uint8_t *IV)
{

  uint32_t ks[Nb*(Nr+1)]; // 44 word key schedule
  keyExpansion(K,&ks[0]);
  uint32_t n = 16/(4*Nb);
  cout << "n = " << n  << endl;

  printf("p = %p c = %p k = %p IV = %p \n", P,C,K,IV);

  uint8_t pp[16];
  for(int i = 0;i <4*Nb;i++)
    {
      cout << "I am here" << endl;
      P[i] = 0;
      cout << "I am here" << endl;
      cout << "i = " << i << hex << " " << (P+i) << dec<< endl;
      printf("plaintext[0] = %02x\n", P[i]);
      printf("IV[0] = %02x\n", IV[i]);
      cout << "p ^ iv = " << hex << (P[i] ^ IV[i]) << dec << endl;
      uint8_t t = P[i] ^ IV[i];
      cout << hex << "p[i] = " << P[i] << " t = "<< t << dec << endl;
      pp[i] = t;
    }


  cipher(&P[0],&C[0],ks);
  for(int b =1; b < n; b++)
    {
      for(int i = 0;i <4*Nb;i++)
	{
	  P[b*(4*Nb)+i] ^= C[(b-1)*(4*Nb)+i];
	}

      cipher(&P[b*(4*Nb)],&C[(b-1)*(4*Nb)],ks);
      
    }

}

int main(void)
{
  aes_128_cbc aes_object;
  uint8_t plainText[16];
  memcpy(plainText, "Single block msg", 16);
  uint8_t key[] = {0x06, 0xa9, 0x21, 0x40, 0x36, 0xb8, 0xa1, 0x5b, 0x51, 0x2e, 0x03, 0xd5, 0x34, 0x12, 0x00, 0x06};
  uint8_t IV[] = {0x3d, 0xaf, 0xba, 0x42, 0x9d, 0x9e, 0xb4, 0x30, 0xb4, 0x22, 0xda, 0x80, 0x2c, 0x9f, 0xac, 0x41};
  uint8_t cipherText[16];
  uint32_t len = 16;

  AES128_CBC_encrypt_buffer(plainText,&cipherText[0],len,&key[0],&IV[0]);
  cout << "ciper = 0x";
  for (int i =0; i < 16; i++)
    {
      cout << hex << setw(2) << setfill('0')<< (uint32_t)cipherText[i] << dec;
    }
  cout << endl;
}
