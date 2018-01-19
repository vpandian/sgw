#include <iostream>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/epoll.h>
#include <iomanip>
#include <endian.h>
#include <sstream>

#include "crypto++/dh.h"
using CryptoPP::DH;
#include "crypto++/integer.h"
using CryptoPP::Integer;
#include "crypto++/nbtheory.h"
using CryptoPP::ModularExponentiation;

#include "hash.hpp"
#include "isakmp.hpp"
//#include "aes.hpp"

#include "sgw.hpp"

using namespace std;


//uint8_t SK_ai[20];
//uint8_t SK_ar[20];
//uint8_t SK_ei[16];
//uint8_t SK_er[16];

//uint8_t i_auth[20];
//uint8_t r_auth[20];
//uint8_t i_enc[16];
//uint8_t r_enc[16];

void prf(uint32_t * K, uint8_t * S, uint32_t s_len, uint32_t *temp_hash)
{
  cout << "s_len = " << s_len << endl;
  uint8_t temp_buf[64];

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
  // copies the remaing and do the transform
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

void endpoint::hasher(uint8_t pad, uint8_t * seed,uint8_t seed_len,uint32_t * hash)
{
  uint8_t temp_buf[64];
  memset(temp_buf,0,64);
  memcpy(temp_buf,nonce_i,num_nonce_i_bytes);
  memcpy(temp_buf+num_nonce_i_bytes,nonce_r,16);

  hmac hmac_1;
  hmac_1.key(temp_buf,64,pad);
  if(seed_len >= 64)
    {
      hmac_1.transform1(seed);
      hmac_1.transform1(seed+64);
      memset(temp_buf,0,64);
      temp_buf[0] = 0x80;
    }
  else
    {
      memset(temp_buf,0, 64);
      memcpy(temp_buf,seed,seed_len);
      temp_buf[seed_len] = 0x80;
    }

  uint32_t * lenp = (uint32_t *)(temp_buf + 60);
  *lenp = htonl((64+seed_len)*8);
  hmac_1.transform1(temp_buf);

  // save the results of step1 in the temp_hash
  hmac_1.result(hash);
}

void endpoint::doCalculation()
{
  stringstream str1;
  str1 << "0x";
  for(int i = 0; i < dh_key_bytes; i++)
    {
      str1 << hex << setw(2) << setfill('0')<< (uint16_t)dh_key[i] << dec;
    }
  Integer dh_public_key(str1.str().c_str()); 

  // dh_shared is the public key 
  shared_key = ModularExponentiation(dh_public_key, dh_a, dh_p);
  cout << "fuck yeah.. shared key = " << hex << shared_key << dec << endl;

  uint8_t shared_key_buf[1024];
  for (int i=0;i<shared_key.ByteCount();i++)      
    shared_key_buf[shared_key.ByteCount()-1-i]=shared_key.GetByte(i); 

  //do the remaning calculation

  uint32_t temp_hash[5];
  hasher(IPAD,shared_key_buf,128,temp_hash);

  uint32_t SKSEED[5];
  hasher(OPAD,(uint8_t *)temp_hash,20,SKSEED);



  cout << "final = " << hex << ntohl(SKSEED[0]) << ntohl(SKSEED[1]) << ntohl(SKSEED[2]) << ntohl(SKSEED[3]) << ntohl(SKSEED[4]) << dec << endl;

  uint64_t n_r_spi = be64toh(rSPI);
  uint64_t h_i_spi = be64toh(iSPI);
  cout << "iSPI = " << hex << setw(16) << setfill('0') << be64toh(iSPI) << dec << endl;
  cout << "rSPI = " << hex << setw(16) << setfill('0') << be64toh(n_r_spi) << dec << endl;
  
  //S = Ni | Nr | SPIi | SPIr
  uint8_t * S = (uint8_t *)malloc(num_nonce_i_bytes + 16 + 8 + 8);
  memcpy(S, nonce_i,num_nonce_i_bytes);
  memcpy(S+num_nonce_i_bytes, nonce_r,16);
  memcpy(S+num_nonce_i_bytes + 16, &iSPI,8);
  memcpy(S+num_nonce_i_bytes + 16 + 8,&rSPI,8);

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

  uint8_t * S1 = (uint8_t *)malloc(num_nonce_i_bytes + 16 + 1+ 8 + 8 + 20);
  uint8_t * S2 = S1 + 20;
  memcpy(S2, nonce_i,num_nonce_i_bytes);
  memcpy(S2+num_nonce_i_bytes, nonce_r,16);
  memcpy(S2+num_nonce_i_bytes + 16, &iSPI,8);
  //memcpy(S2+num_nonce_i_bytes + 16, &h_i_spi,8);
  //memcpy(S2+num_nonce_i_bytes + 16 +8, &rSPI,8);
  memcpy(S2+num_nonce_i_bytes + 16 +8, &n_r_spi,8);
  S2[num_nonce_i_bytes + 16 + 8 + 8] = 0x01;
  prf(SKSEED,S2,num_nonce_i_bytes + 16 + 8 + 8+1, T1);
  cout << "T1 = " << hex << htonl(T1[0]) << htonl(T1[1]) << htonl(T1[2]) << htonl(T1[3]) << htonl(T1[4]) << dec << endl;
  
  // Now T2
  memcpy(S1,T1,20);
  S2[num_nonce_i_bytes + 16 + 8 + 8] = 0x02;
  prf(SKSEED,S1,num_nonce_i_bytes + 16 + 8 + 8+1+20, T2);
  memcpy(SK_ai,T2,20);

  cout << "T2 (SK_ai) = "
       << setw(8) << setfill('0') << hex << htonl(T2[0])
       << setw(8) << setfill('0') << htonl(T2[1])
       << setw(8) << setfill('0') << htonl(T2[2])
       << setw(8) << setfill('0') << htonl(T2[3]) << htonl(T2[4]) << dec << endl;
  

  // Now T3
  memcpy(S1,T2,20);
  S2[num_nonce_i_bytes + 16 + 8 + 8] = 0x03;
  prf(SKSEED,S1,num_nonce_i_bytes + 16 + 8 + 8+1+20, T3);
  memcpy(SK_ar,T3,20);
  cout << "T3 = (SK_ar) "
       << setw(8) << setfill('0') << hex << htonl(T3[0])
       << setw(8) << setfill('0') << htonl(T3[1])
       << setw(8) << setfill('0') << htonl(T3[2])
       << setw(8) << setfill('0') << htonl(T3[3])
       << setw(8) << setfill('0') << htonl(T3[4]) << dec << endl;
  
  // Now T4
  memcpy(S1,T3,20);
  S2[num_nonce_i_bytes + 16 + 8 + 8] = 0x04;
  prf(SKSEED,S1,num_nonce_i_bytes + 16 + 8 + 8+1+20, T4);
  memcpy(SK_ei,T4,16);
  memcpy(SK_er,T4+4,4);
  cout << "T4 = " << setw(8) << setfill('0') << hex << htonl(T4[0])
       << setw(8) << setfill('0') << htonl(T4[1])
       << setw(8) << setfill('0') << htonl(T4[2])
       << setw(8) << setfill('0') << htonl(T4[3])
       << setw(8) << setfill('0') << htonl(T4[4]) << dec << endl;
  cout << "SK_ei =  "
       << setw(8) << setfill('0') << hex << htonl(T4[0])
       << setw(8) << setfill('0') << htonl(T4[1])
       << setw(8) << setfill('0') << htonl(T4[2])
       << setw(8) << setfill('0') << htonl(T4[3]) << dec << endl;

  // Now T5
  memcpy(S1,T4,20);
  S2[num_nonce_i_bytes + 16 + 8 + 8] = 0x05;
  prf(SKSEED,S1,num_nonce_i_bytes + 16 + 8 + 8+1+20, T5);
  memcpy(SK_er+4,T5,12);
  memcpy(SK_pi,T5+3,8);
  cout << "T5 = (remaining 12-bytes of SK_er and first 8 bytes of SK_pi) " << setw(8) << setfill('0') << hex << htonl(T5[0]) << htonl(T5[1]) << htonl(T5[2]) << htonl(T5[3]) << htonl(T5[4]) << dec << endl;
  cout << "sk_er = "
       << setw(8) << setfill('0') << hex << htonl(T4[4])
       << setw(8) << setfill('0') << htonl(T5[0])
       << setw(8) << setfill('0') << htonl(T5[1])
       << setw(8) << setfill('0') << htonl(T5[2]) << dec << endl;

  
  
  // Now T6
  memcpy(S1,T5,20);
  S2[num_nonce_i_bytes + 16 + 8 + 8] = 0x06;
  prf(SKSEED,S1,num_nonce_i_bytes + 16 + 8 + 8+1+20, T6);
  cout << "T6 = (remaining 12 bytes of SK_pi and first 8 bytes of SK_pr) " << setw(8) << setfill('0') << hex << htonl(T6[0]) << htonl(T6[1]) << htonl(T6[2]) << htonl(T6[3]) << htonl(T6[4]) << dec << endl;
  memcpy(SK_pi+8,T6,12);
  memcpy(SK_pr,T6+3,8);

  // Now T7
  memcpy(S1,T6,20);
  S2[num_nonce_i_bytes + 16 + 8 + 8] = 0x07;
  prf(SKSEED,S1,num_nonce_i_bytes + 16 + 8 + 8+1+20, T7);
  cout << "T7 = (remaining 12 bytes of SK_pr) " << hex << htonl(T7[0]) << htonl(T7[1]) << htonl(T7[2]) << htonl(T7[3]) << htonl(T7[4]) << dec << endl;
  memcpy(SK_pr+8,T7,12);

  // ipsec keys
  memcpy(S2, nonce_i,num_nonce_i_bytes);
  memcpy(S2+num_nonce_i_bytes, nonce_r,16);

  S2[num_nonce_i_bytes + 16] = 0x01;
  prf(T1,S2,num_nonce_i_bytes + 16 + 1, T8);
  cout << "T8 = " << hex << setw(8) << setfill('0') << htonl(T8[0]) << htonl(T8[1]) << htonl(T8[2]) << htonl(T8[3]) << htonl(T8[4]) << dec << endl;
  
  // Now T2
  memcpy(S1,T8,20);
  S2[num_nonce_i_bytes + 16] = 0x02;
  prf(T1,S1,num_nonce_i_bytes + 16+1+20, T9);

  cout << "T9 = " << hex << setw(8) << setfill('0') << htonl(T9[0]) << htonl(T9[1]) << htonl(T9[2]) << htonl(T9[3]) << htonl(T9[4]) << dec << endl;
  

  // Now T3
  memcpy(S1,T9,20);
  S2[num_nonce_i_bytes + 16] = 0x03;
  prf(T1,S1,num_nonce_i_bytes + 16 +1+20, T10);

  cout << "T10 = " << hex << setw(8) << setfill('0') << htonl(T10[0]) << htonl(T10[1]) << htonl(T10[2]) << htonl(T10[3]) << htonl(T10[4]) << dec << endl;
  
  // Now T4
  memcpy(S1,T10,20);
  S2[num_nonce_i_bytes + 16] = 0x04;
  prf(T1,S1,num_nonce_i_bytes + 16 +1+20, T11);

  cout << "T11 = " << hex << setw(8) << setfill('0') << htonl(T11[0]) << htonl(T11[1]) << htonl(T11[2]) << htonl(T11[3]) << htonl(T11[4]) << dec << endl;
  
  cout << "encr inbound = " << hex << setw(8) << setfill('0') << htonl(T8[0]) << " " << htonl(T8[1]) << " " << htonl(T8[2]) << " " << htonl(T8[3]) << dec << endl;
  memcpy(i_enc,T8,16);

  cout << "auth inbound = " << hex << setw(8) << setfill('0') << htonl(T8[4]) << " " << htonl(T9[0]) << " " << htonl(T9[1])<< " " << htonl(T9[2]) << " " << htonl(T9[3])<< dec << endl;

  cout << "encr outbound = " << hex << setw(8) << setfill('0') << htonl(T9[4]) << " " <<htonl(T10[0]) << " "<< htonl(T10[1]) << " " << htonl(T10[2]) << dec << endl;
  //memcpy(r_enc,T11,16);
  //memcpy(r_enc,T11,16);


  cout << "auth outbound = " << hex << setw(8) << setfill('0') << htonl(T10[3]) << " " << htonl(T10[4]) << " " << htonl(T11[0]) << " " << htonl(T11[1]) << " " << htonl(T11[2]) << dec << endl;

  cout << "************** ep(1) = " << this << endl;


  cout << "r nonce = " << hex <<  setw(2) << setfill('0') << (uint32_t)nonce_r[0] <<  (uint32_t)nonce_r[1] <<  (uint32_t)nonce_r[2] <<  (uint32_t)nonce_r[3] << endl;
  cout << "i nonce = " << hex <<  setw(2) << setfill('0') << (uint32_t)nonce_i[0] <<  (uint32_t)nonce_i[1] <<  (uint32_t)nonce_i[2] <<  (uint32_t)nonce_i[3] << endl;

  hmac hmac_3;


  uint8_t temp_buf[64];
  memset(temp_buf,0, 64);
  memcpy(temp_buf,SKSEED,20);
  hmac_3.key(temp_buf,64,IPAD);

  hmac_3.transform1(S);
  //hmac_3.transform(S, sizeof(a6) +sizeof(a7) + sizeof(SPIi) +sizeof(SPIr));

  memset(temp_buf,0, 64);
  temp_buf[0] = 0x01;

  temp_buf[1] = 0x80;
  uint32_t * lenp = (uint32_t *)(temp_buf + 60);
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
  cout << "Done with do calculation" << endl;
  //T2 = prf (K, T1 | S | 0x02)

}
