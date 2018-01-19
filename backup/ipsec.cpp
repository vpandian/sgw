#include <iostream>
#include <fstream>
#include <stdint.h>
#include <iomanip>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stdlib.h>
#include <string.h>
#include <sstream>

#include "crypto++/dh.h"
using CryptoPP::DH;
#include "crypto++/integer.h"
using CryptoPP::Integer;
#include "crypto++/nbtheory.h"
using CryptoPP::ModularExponentiation;


#include "hash.hpp"
#include "isakmp.hpp"
#include "aes.hpp"

uint8_t SK_ai[20];
uint8_t SK_ar[20];
uint8_t SK_ei[16];
uint8_t SK_er[16];


uint8_t i_auth[20];
uint8_t r_auth[20];
uint8_t i_enc[16];
uint8_t r_enc[16];

using namespace std;

const uint8_t IPAD = 0x36;
const uint8_t OPAD = 0x5C;
uint32_t packet_count = 0;

//--------------------------------
// Author: Vijay Pandian
// No one else touched the code
//--------------------------------


//Alice and Bob agree to use a modulus p = 23 and base g = 5 (which is a primitive root modulo 23).
//Alice chooses a secret integer a = 6, then sends Bob A = ga mod p (nonce)
//A = 5^6 mod 23 = 8
//Bob chooses a secret integer b = 15, then sends Alice B = gb mod p (nonce)
//B = 5^15 mod 23 = 19
//Alice computes s = B^a mod p - symmetric key g^(ab) modp
//s = 19^6 mod 23 = 2
//Bob computes s = A^b mod p - symmetric key g^(ab) modp
//s = 8^15 mod 23 = 2
//Alice and Bob now share a secret (the number 2).

void prf(uint32_t * K, uint8_t * S, uint32_t s_len, uint32_t *temp_hash)
{

  cout << "s_len = " << s_len << endl;
  uint8_t * temp_buf  = (uint8_t *)malloc(64);

  hmac hmac_3;

  memset(temp_buf,0, 64);
  memcpy(temp_buf,K,20);
  hmac_3.key(temp_buf,64,IPAD);


  // split it into 64 bytes and do the transform
  uint32_t nb = s_len/64;
  cout << "nb = " << nb << endl;
  cout << "s_len%64 = " << s_len%64 << endl;
  
  for(uint32_t i = 0;i < nb;i ++)
    {
      hmac_3.transform1(S+(i*64));
    }


  memset(temp_buf,0, 64);
  memcpy(temp_buf,S+(64*nb),s_len%64);
  temp_buf[s_len%64] = 0x80;
  uint32_t * lenp = (uint32_t *)(temp_buf + 60);
  *lenp = htonl((64+s_len)*8);
  hmac_3.transform1(temp_buf);
  //hmac_3.transform(a8, sizeof(a8));


  hmac_3.result(&temp_hash[0]);


  hmac hmac_4;

  memset(temp_buf,0, 64);
  memcpy(temp_buf,K,20);
  hmac_4.key(temp_buf,64, OPAD);

  memset(temp_buf,0, 64);
  memcpy(temp_buf,temp_hash,20);
  temp_buf[20] = 0x80;
  *lenp = htonl((64+20)*8);
  hmac_4.transform1(temp_buf);
  //hmac_4.transform(a8, sizeof(a8));
  
  hmac_4.result(&temp_hash[0]);

}

void doCalculation()
{
  stringstream str1;
  str1 << "0x";
  for(int i = 0; i < ep->dh_key_bytes; i++)
    {
      str1 << hex << setw(2) << setfill('0')<< (uint16_t)ep->dh_key[i] << dec;
    }
  Integer dh_public_key(str1.str().c_str()); 

  // dh_shared is the public key 
  shared_key = ModularExponentiation(dh_public_key, dh_a, dh_p);
  cout << "fuck yeah.. shared key = " << hex << shared_key << dec << endl;

  uint8_t shared_key_buf[1024];
  for (int i=0;i<shared_key.ByteCount();i++)      
    shared_key_buf[shared_key.ByteCount()-1-i]=shared_key.GetByte(i); 


  //do the remaning calculation
  uint8_t hex_val = 0x01;

  uint8_t * temp_buf  = (uint8_t *)malloc(64);
  memset(temp_buf,0,64);
  memcpy(temp_buf,ep->nonce_i,ep->num_nonce_i_bytes);
  memcpy(temp_buf+ep->num_nonce_i_bytes,ep->nonce_r,16);


  hmac hmac_1;
  hmac_1.key(temp_buf,64,IPAD);
  hmac_1.transform1(shared_key_buf);
  hmac_1.transform1(shared_key_buf+64);

  memset(temp_buf,0,64);
  temp_buf[0] = 0x80;
  uint32_t * lenp = (uint32_t *)(temp_buf + 60);
  *lenp = htonl((64+128)*8);
  hmac_1.transform1(temp_buf);

  // save the results of step1 in the temp_hash
  uint32_t temp_hash[5];
  hmac_1.result(&temp_hash[0]);

  hmac hmac_2;
  //o_key_pad = [0x5c * blocksize] ⊕ key // Where blocksize is that of the underlying hash function

  memset(temp_buf,0, 64);
  memcpy(temp_buf,ep->nonce_i,ep->num_nonce_i_bytes);
  memcpy(temp_buf+ep->num_nonce_i_bytes,ep->nonce_r,16);
  hmac_2.key(temp_buf,64, OPAD);
  
  memset(temp_buf,0, 64);
  memcpy(temp_buf,temp_hash,20);

  temp_buf[20] = 0x80;
  //uint32_t * lenp = (uint32_t *)(a8 + 60);
  *lenp = htonl((64+20)*8);
  hmac_2.transform1(temp_buf);
  //hmac_2.transform(a8, 64);

  uint32_t SKSEED[5];
  hmac_2.result(&SKSEED[0]);
  cout << "final = " << hex << ntohl(SKSEED[0]) << ntohl(SKSEED[1]) << ntohl(SKSEED[2]) << ntohl(SKSEED[3]) << ntohl(SKSEED[4]) << dec << endl;

  //S = Ni | Nr | SPIi | SPIr
  uint8_t * S = (uint8_t *)malloc(ep->num_nonce_i_bytes + 16 + 8 + 8);
  memcpy(S, ep->nonce_i,ep->num_nonce_i_bytes);
  memcpy(S+ep->num_nonce_i_bytes, ep->nonce_r,16);
  memcpy(S+ep->num_nonce_i_bytes + 16, ep->iSPI,8);
  memcpy(S+ep->num_nonce_i_bytes + 16 + 8,ep->rSPI,8);

  //T1 = prf (K, S | 0x01)
  //T2 = prf (K, T1 | S | 0x02)
  //T3 = prf (K, T2 | S | 0x03)
  //T4 = prf (K, T3 | S | 0x04)

  uint32_t T1[5];
  uint32_t T2[5];
  uint32_t T3[5];
  uint32_t T4[5];
  uint32_t T5[5];
  uint32_t T6[5];
  uint32_t T7[5];
  uint32_t T8[5];
  uint32_t T9[5];
  uint32_t T10[5];
  uint32_t T11[5];
  uint32_t T12[5];

  uint8_t * S1 = (uint8_t *)malloc(ep->num_nonce_i_bytes + 16 + 1+ 8 + 8 + 20);
  uint8_t * S2 = S1 + 20;
  memcpy(S2, ep->nonce_i,ep->num_nonce_i_bytes);
  memcpy(S2+ep->num_nonce_i_bytes, ep->nonce_r,16);
  memcpy(S2+ep->num_nonce_i_bytes + 16, ep->iSPI,8);
  memcpy(S2+ep->num_nonce_i_bytes + 16 +8, ep->rSPI,8);
  S2[ep->num_nonce_i_bytes + 16 + 8 + 8] = 0x01;
  prf(SKSEED,S2,ep->num_nonce_i_bytes + 16 + 8 + 8+1, T1);
  cout << "T1 = " << hex << htonl(T1[0]) << htonl(T1[1]) << htonl(T1[2]) << htonl(T1[3]) << htonl(T1[4]) << dec << endl;
  
  // Now T2
  memcpy(S1,T1,20);
  S2[ep->num_nonce_i_bytes + 16 + 8 + 8] = 0x02;
  prf(SKSEED,S1,ep->num_nonce_i_bytes + 16 + 8 + 8+1+20, T2);
  memcpy(SK_ai,T2,20);

  cout << "T2 = " << hex << htonl(T2[0]) << htonl(T2[1]) << htonl(T2[2]) << htonl(T2[3]) << htonl(T2[4]) << dec << endl;
  

  // Now T3
  memcpy(S1,T2,20);
  S2[ep->num_nonce_i_bytes + 16 + 8 + 8] = 0x03;
  prf(SKSEED,S1,ep->num_nonce_i_bytes + 16 + 8 + 8+1+20, T3);
  memcpy(SK_ar,T3,20);
  cout << "T3 = " << hex << htonl(T3[0]) << htonl(T3[1]) << htonl(T3[2]) << htonl(T3[3]) << htonl(T3[4]) << dec << endl;
  
  // Now T4
  memcpy(S1,T3,20);
  S2[ep->num_nonce_i_bytes + 16 + 8 + 8] = 0x04;
  prf(SKSEED,S1,ep->num_nonce_i_bytes + 16 + 8 + 8+1+20, T4);
  memcpy(SK_ei,T4,16);
  memcpy(SK_er,T4+4,4);
  cout << "T4 = " << hex << htonl(T4[0]) << htonl(T4[1]) << htonl(T4[2]) << htonl(T4[3]) << htonl(T4[4]) << dec << endl;
  
  // Now T5
  memcpy(S1,T4,20);
  S2[ep->num_nonce_i_bytes + 16 + 8 + 8] = 0x05;
  prf(SKSEED,S1,ep->num_nonce_i_bytes + 16 + 8 + 8+1+20, T5);
  memcpy(SK_er+4,T5,12);
  cout << "T5 = " << hex << htonl(T5[0]) << htonl(T5[1]) << htonl(T5[2]) << htonl(T5[3]) << htonl(T5[4]) << dec << endl;
  
  // Now T6
  memcpy(S1,T5,20);
  S2[ep->num_nonce_i_bytes + 16 + 8 + 8] = 0x06;
  prf(SKSEED,S1,ep->num_nonce_i_bytes + 16 + 8 + 8+1+20, T6);
  cout << "T6 = " << hex << htonl(T6[0]) << htonl(T6[1]) << htonl(T6[2]) << htonl(T6[3]) << htonl(T6[4]) << dec << endl;

  // Now T7
  memcpy(S1,T6,20);
  S2[ep->num_nonce_i_bytes + 16 + 8 + 8] = 0x07;
  prf(SKSEED,S1,ep->num_nonce_i_bytes + 16 + 8 + 8+1+20, T7);
  cout << "T7 = " << hex << htonl(T7[0]) << htonl(T7[1]) << htonl(T7[2]) << htonl(T7[3]) << htonl(T7[4]) << dec << endl;

  // ipsec keys
  memcpy(S2, ep->nonce_i,ep->num_nonce_i_bytes);
  memcpy(S2+ep->num_nonce_i_bytes, ep->nonce_r,16);

  S2[ep->num_nonce_i_bytes + 16] = 0x01;
  prf(T1,S2,ep->num_nonce_i_bytes + 16 + 1, T8);
  cout << "T8 = " << hex << setw(8) << setfill('0') << htonl(T8[0]) << htonl(T8[1]) << htonl(T8[2]) << htonl(T8[3]) << htonl(T8[4]) << dec << endl;
  
  // Now T2
  memcpy(S1,T8,20);
  S2[ep->num_nonce_i_bytes + 16] = 0x02;
  prf(T1,S1,ep->num_nonce_i_bytes + 16+1+20, T9);

  cout << "T9 = " << hex << setw(8) << setfill('0') << htonl(T9[0]) << htonl(T9[1]) << htonl(T9[2]) << htonl(T9[3]) << htonl(T9[4]) << dec << endl;
  

  // Now T3
  memcpy(S1,T9,20);
  S2[ep->num_nonce_i_bytes + 16] = 0x03;
  prf(T1,S1,ep->num_nonce_i_bytes + 16 +1+20, T10);

  cout << "T10 = " << hex << setw(8) << setfill('0') << htonl(T10[0]) << htonl(T10[1]) << htonl(T10[2]) << htonl(T10[3]) << htonl(T10[4]) << dec << endl;
  
  // Now T4
  memcpy(S1,T10,20);
  S2[ep->num_nonce_i_bytes + 16] = 0x04;
  prf(T1,S1,ep->num_nonce_i_bytes + 16 +1+20, T11);

  cout << "T11 = " << hex << setw(8) << setfill('0') << htonl(T11[0]) << htonl(T11[1]) << htonl(T11[2]) << htonl(T11[3]) << htonl(T11[4]) << dec << endl;
  
  cout << "encr inbound = " << hex << setw(8) << setfill('0') << htonl(T8[0]) << htonl(T8[1]) << htonl(T8[2]) << htonl(T8[3]) << dec << endl;
  memcpy(i_enc,T8,16);

  cout << "auth inbound = " << hex << setw(8) << setfill('0') << htonl(T8[4]) << htonl(T9[0]) << htonl(T9[1]) << htonl(T9[2]) << htonl(T9[3])<< dec << endl;

  cout << "encr outbound = " << hex << setw(8) << setfill('0') << htonl(T9[4]) << htonl(T10[0]) << htonl(T10[1]) << htonl(T10[2]) << dec << endl;
  //memcpy(r_enc,T11,16);
  //memcpy(r_enc,T11,16);


  cout << "auth outbound = " << hex << setw(8) << setfill('0') << htonl(T10[3]) << htonl(T10[4]) << htonl(T11[0]) << htonl(T11[1]) << htonl(T11[2]) << dec << endl;


  hmac hmac_3;



  memset(temp_buf,0, 64);
  memcpy(temp_buf,SKSEED,20);
  hmac_3.key(temp_buf,64,IPAD);

  hmac_3.transform1(S);
  //hmac_3.transform(S, sizeof(a6) +sizeof(a7) + sizeof(SPIi) +sizeof(SPIr));

  memset(temp_buf,0, 64);
  temp_buf[0] = 0x01;

  temp_buf[1] = 0x80;
  *lenp = htonl((64+64+1)*8);
  hmac_3.transform1(temp_buf);
  //hmac_3.transform(a8, sizeof(a8));

  hmac_3.result(&temp_hash[0]);

  hmac hmac_4;

  memset(temp_buf,0, 64);
  memcpy(temp_buf,SKSEED,20);
  hmac_4.key(temp_buf,64, OPAD);

  memset(temp_buf,0, 64);
  memcpy(temp_buf,temp_hash,20);
  temp_buf[20] = 0x80;
  *lenp = htonl((64+20)*8);
  hmac_4.transform1(temp_buf);
  //hmac_4.transform(a8, sizeof(a8));
  
  hmac_4.result(&temp_hash[0]);
  cout << "T1 = " << hex << htonl(temp_hash[0]) << htonl(temp_hash[1]) << htonl(temp_hash[2]) << htonl(temp_hash[3]) << htonl(temp_hash[4]) << dec << endl;

  //T2 = prf (K, T1 | S | 0x02)

}
