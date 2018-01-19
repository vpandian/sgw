#include <stdint.h>
#include <arpa/inet.h>
#include <iostream>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include "hash.hpp"

const uint32_t K0 = 0x5A827999;
const uint32_t K1 = 0x6ED9EBA1;
const uint32_t K2 = 0x8F1BBCDC;
const uint32_t K3 = 0xCA62C1D6;

const uint8_t IPAD = 0x36;
const uint8_t OPAD = 0x5C;
const uint8_t BLOCK_SIZE = 64;

inline
uint32_t rotate_left(uint32_t v, const uint8_t p)
{
  return ((v << p) | ( v >> (32 - p))); 
}

sha1::sha1()
{
  h0 = 0x67452301;
  h1 = 0xEFCDAB89;
  h2 = 0x98BADCFE;
  h3 = 0x10325476;
  h4 = 0xC3D2E1F0;
}


void sha1::transform1(uint8_t * data)
{

  uint32_t w[80];
  uint32_t *data32 = (uint32_t *) data;
  for(int i= 0;i<16;i++)
    {
      w[i] = htonl(data32[i]);
    }
  for (int i = 16; i < 80; i++)
    {
      w[i] = w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16];
      w[i] = rotate_left(w[i],1);
    }
  uint32_t a = h0;
  uint32_t b = h1;
  uint32_t c = h2;
  uint32_t d = h3;
  uint32_t e = h4;
  for(int i = 0; i < 20; i++)
    {
      uint32_t f = (b & c) ^ ((~b) & d);
      uint32_t temp = rotate_left(a,5) + f + e + K0 + w[i];
      e = d;
      d = c;
      c = rotate_left(b,30);
      b = a;
      a = temp;
    }
 
  for(int i = 20; i < 40; i++)
    {
      uint32_t f = (b ^ c ^ d);
      uint32_t temp = rotate_left(a,5) + f + e + K1 + w[i];
      e = d;
      d = c;
      c = rotate_left(b,30);
      b = a;
      a = temp;
    }
 
  for(int i = 40; i < 60; i++)
    {
      uint32_t f = (b & c) ^ (b & d) ^ (c & d);
      uint32_t temp = rotate_left(a,5) + f + e + K2 + w[i];
      e = d;
      d = c;
      c = rotate_left(b,30);
      b = a;
      a = temp;
    }
 
  for(int i = 60; i < 80; i++)
    {
      uint32_t f = (b ^ c ^ d);
      uint32_t temp = rotate_left(a,5) + f + e + K3 + w[i];
      e = d;
      d = c;
      c = rotate_left(b,30);
      b = a;
      a = temp;
    }
  h0 = h0 + a;
  h1 = h1 + b;
  h2 = h2 + c;
  h3 = h3 + d;
  h4 = h4 + e;
}

void hmac::key(uint8_t * k, uint32_t len, uint8_t pad)
{
  //i_key_pad = [0x36 * blocksize] ⊕ key // Where ⊕ is exclusive or (XOR)
  for(int i =0;i < len;i++)
    {
      k[i] ^= pad;
    }
  transform1(k);
}

void hmac::transform(uint8_t * data, uint32_t len)
{
  for(int i = 0; i < len; i += BLOCK_SIZE)
    {
      transform1(data+i);
    }
}

void hmac::final()
{
  // Construct another 64 byte block.
  // byte[0] = 0x80
  // byte[1] to byte[55] = 0x00
  // byte[56] to byte[59] = high order 32 bit of length of data in bits.
  // byte[60] to byte[63] = low order 32 bit of length of data in bits.

  uint8_t * a8 = (uint8_t *)malloc(64);
  memset(a8,0,64);
  a8[0] = 0x80;
  uint32_t * lenp = (uint32_t *)(a8 + 60);
  *lenp = htonl((64+128)*8);
  transform1(a8);
}

void hmac::result(uint32_t * buf)
{
  *buf =ntohl(h0);
  *(buf+1) = ntohl(h1);
  *(buf+2) = ntohl(h2);
  *(buf+3) = ntohl(h3);
  *(buf+4) = ntohl(h4);
}
