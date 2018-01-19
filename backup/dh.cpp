#include <iostream>
#include <math.h>
#include <cstdlib>
#include <ctime>
#include <stdint.h>
#include <boost/multiprecision/cpp_int.hpp>
#include <openssl/sha.h>
#include <boost/multiprecision/cpp_dec_float.hpp>
#include <arpa/inet.h>
#include "crypto++/dh.h"

#include "hash.hpp"

using CryptoPP::DH;

#include "crypto++/integer.h"
using CryptoPP::Integer;
#include "crypto++/nbtheory.h"
using CryptoPP::ModularExponentiation;

#include "crypto++/secblock.h"
using CryptoPP::SecByteBlock;

#include <crypto++/hex.h>
using CryptoPP::HexEncoder;

#include <crypto++/filters.h>
using CryptoPP::StringSink;

#include "crypto++/osrng.h"
using CryptoPP::AutoSeededRandomPool;

//#include <cryptopp/sha.h>
//using CryptoPP::SHA;

using namespace std;
//using namespace boost::multiprecision;

const uint8_t IPAD = 0x36;
const uint8_t OPAD = 0x5C;

uint64_t create_public_key(boost::multiprecision::uint1024_t pn, uint32_t gn, boost::multiprecision::uint256_t s_key)
{
  Integer a1("0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF");
  Integer a2("0x02");
  Integer a3("0x6FD5DECDE27F00006FD5DECDE27F00006FD5DECDE27F0000");
  
  Integer a5("0xc842059baf0b6a9e414b8ca123a1533608dae32226b8f74737d0eea54106302dd2f8442bf3e89737f68f3f76bec059eab8ad0f260e816aeddbf3ca46f435e2fbe44f41834feef63dd937017ecd3007a97a1fba75a7ea022225f060af738a33b835c85c56a19ba7e9ac20d2ec1920c2204a2dead74a2ef4f3007714fc1826a5c3");

  Integer a4 = ModularExponentiation(a5,a3,a1);
  cout << "a5 = " << hex << a5 << dec << endl;
  cout << "a4 = " << hex << a4 << dec << endl;
  uint8_t a4_buf[1024];
  cout << "a4 byte count = " << a4.ByteCount() << endl;
  for (int i=0;i<a4.ByteCount();i++)      
    a4_buf[a4.ByteCount()-1-i]=a4.GetByte(i); 
  cout << "Actual a4 value = "<< endl;
  for(int i=0;i < a4.ByteCount();i++)
    {
      cout << hex << (uint32_t)a4_buf[i]<< dec;
    }
  cout << endl;

  uint8_t a6[] = {
                   0xe4, 0xd5, 0x2b, 0x5e, 0x55, 0x31, 0xef, 0xc5, 0x02, 0x8a, 0xb9, 0x00, 0x0f, 0xdd, 0x22, 0x23, 0x42,
		   0x9f, 0x59, 0xc6, 0x50, 0xe0, 0x26, 0xd0, 0x4c, 0x9f, 0xab, 0xb6, 0x18, 0x42, 0xa2, 0x54
	          };
  
  uint8_t a7[] = {0xcf, 0xd5, 0xde, 0xcd, 0xe2, 0x7f, 0x00, 0x00,0xcf, 0xd5, 0xde, 0xcd, 0xe2, 0x7f, 0x00, 0x00};
 
  uint8_t SPIi[] = {0xe8, 0xe9, 0xa4, 0x1c, 0xc8, 0xb4, 0xe1, 0xeb};
  uint8_t SPIr[] = {0x31, 0x20, 0x80, 0x00, 0xcf, 0xd5, 0xde, 0xcd};

  uint8_t hex_val = 0x01;
  uint8_t * a8 = (uint8_t *)malloc(64);
  memset(a8,0, 64);
  memcpy(a8,a6,sizeof(a6));
  memcpy(a8+sizeof(a6),a7,sizeof(a7));

  hmac hmac_1;
  hmac_1.key(a8,64, IPAD);
  hmac_1.transform1(a4_buf);
  hmac_1.transform1(a4_buf+64);
  //hmac_1.transform(a4_buf, a4.ByteCount());

  memset(a8,0,64);
  a8[0] = 0x80;
  uint32_t * lenp = (uint32_t *)(a8 + 60);
  *lenp = htonl((64+128)*8);
  hmac_1.transform1(a8);
  //hmac_1.final();

  // save the results of step1 in the temp_hash
  uint32_t temp_hash[5];
  hmac_1.result(&temp_hash[0]);

  hmac hmac_2;
  //o_key_pad = [0x5c * blocksize] ⊕ key // Where blocksize is that of the underlying hash function

  memset(a8,0, 64);
  memcpy(a8,a6,sizeof(a6));
  memcpy(a8+sizeof(a6),a7,sizeof(a7));
  hmac_2.key(a8,64, OPAD);
  
  memset(a8,0, 64);
  memcpy(a8,temp_hash,20);

  a8[20] = 0x80;
  //uint32_t * lenp = (uint32_t *)(a8 + 60);
  *lenp = htonl((64+20)*8);
  hmac_2.transform1(a8);
  //hmac_2.transform(a8, 64);

  uint32_t SKSEED[5];
  hmac_2.result(&SKSEED[0]);
  cout << "final = " << hex << ntohl(SKSEED[0]) << ntohl(SKSEED[1]) << ntohl(SKSEED[2]) << ntohl(SKSEED[3]) << ntohl(SKSEED[4]) << dec << endl;

  //{SK_d | SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr } = prf+ (SKEYSEED, Ni | Nr | SPIi | SPIr )
  //T1 = prf (K, S | 0x01)
  //T2 = prf (K, T1 | S | 0x02)
  //T3 = prf (K, T2 | S | 0x03)
  //T4 = prf (K, T3 | S | 0x04)

  uint8_t * S = (uint8_t *)malloc(sizeof(a6) +sizeof(a7) + sizeof(SPIi) +sizeof(SPIr));
  memcpy(S,a6,sizeof(a6));
  memcpy(S+sizeof(a6),a7,sizeof(a7));
  memcpy(S+sizeof(a6)+sizeof(a7),SPIi,sizeof(SPIi));
  memcpy(S+sizeof(a6) + sizeof(a7) + sizeof(SPIi) ,SPIr,sizeof(SPIr));


  hmac hmac_3;

  memset(a8,0, 64);
  memcpy(a8,SKSEED,20);
  hmac_3.key(a8,64,IPAD);

  hmac_3.transform1(S);
  //hmac_3.transform(S, sizeof(a6) +sizeof(a7) + sizeof(SPIi) +sizeof(SPIr));
  cout <<"size of S = " << sizeof(a6) +sizeof(a7) + sizeof(SPIi) +sizeof(SPIr) << endl;

  memset(a8,0, 64);
  a8[0] = 0x01;

  a8[1] = 0x80;
  *lenp = htonl((64+64+1)*8);
  hmac_3.transform1(a8);
  //hmac_3.transform(a8, sizeof(a8));


  hmac_3.result(&temp_hash[0]);


  hmac hmac_4;

  memset(a8,0, 64);
  memcpy(a8,SKSEED,20);
  hmac_4.key(a8,64, OPAD);

  memset(a8,0, 64);
  memcpy(a8,temp_hash,20);
  a8[20] = 0x80;
  *lenp = htonl((64+20)*8);
  hmac_4.transform1(a8);
  //hmac_4.transform(a8, sizeof(a8));
  
  hmac_4.result(&temp_hash[0]);
  cout << "T1 = " << hex << htonl(temp_hash[0]) << htonl(temp_hash[1]) << htonl(temp_hash[2]) << htonl(temp_hash[3]) << htonl(temp_hash[4]) << dec << endl;

 #if 0
  hash.Update(pbOutputBuffer, sizeof(pbOutputBuffer));
  hash.Update(a11, sizeof(a6) + sizeof(a7) + sizeof(a9) + sizeof(a10));
  hash.Final(pbOutputBuffer1);

  cout << "S in prf = "<< endl;
  for(int i=0; i < sizeof(pbOutputBuffer1);i++)
    {
      cout << hex << (uint32_t)pbOutputBuffer1[i] << dec;
    }
  cout << endl;

  uint8_t * a13 = (uint8_t *)malloc(sizeof(pbOutputBuffer1) +sizeof(a12));
  memcpy(a13,pbOutputBuffer1,sizeof(pbOutputBuffer1));
  memcpy(a13+sizeof(pbOutputBuffer1),a12,sizeof(12));
  hash.Update(pbOutputBuffer, sizeof(pbOutputBuffer));
  hash.Update(a13, sizeof(pbOutputBuffer1)+sizeof(a12));
  hash.Final(pbOutputBuffer2);

  cout << "T1 = "<< endl;
  for(int i=0; i < sizeof(pbOutputBuffer2);i++)
    {
      cout << hex << (uint32_t)pbOutputBuffer2[i] << dec;
    }
  cout << endl;
#endif

 uint64_t div = 1234;
 return div;
}


int main()
{
  uint32_t dh_g = 2;
  uint8_t dh_p_temp[128] = {
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xc9,0x0f,0xda,0xa2,0x21,0x68,0xc2,0x34,
    0xc4,0xc6,0x62,0x8b,0x80,0xdc,0x1c,0xd1,0x29,0x02,0x4e,0x08,0x8a,0x67,0xcc,0x74,
    0x02,0x0b,0xbe,0xa6,0x3b,0x13,0x9b,0x22,0x51,0x4a,0x08,0x79,0x8e,0x34,0x04,0xdd,
    0xef,0x95,0x19,0xb3,0xcd,0x3a,0x43,0x1b,0x30,0x2b,0x0a,0x6d,0xf2,0x5f,0x14,0x37,
    0x4f,0xe1,0x35,0x6d,0x6d,0x51,0xc2,0x45,0xe4,0x85,0xb5,0x76,0x62,0x5e,0x7e,0xc6,
    0xf4,0x4c,0x42,0xe9,0xa6,0x37,0xed,0x6b,0x0b,0xff,0x5c,0xb6,0xf4,0x06,0xb7,0xed,
    0xee,0x38,0x6b,0xfb,0x5a,0x89,0x9f,0xa5,0xae,0x9f,0x24,0x11,0x7c,0x4b,0x1f,0xe6,
    0x49,0x28,0x66,0x51,0xec,0xe6,0x53,0x81,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
  };

  boost::multiprecision::uint1024_t dh_p = 0;
  for(int i = 0; i < 128; i++)
    {
      dh_p <<= 8;
      dh_p |= dh_p_temp[i];
    }

  cout << "dh_p = " << hex << dh_p << dec << endl;

  uint8_t dh_a_temp[24] = {
      0x6f,0xd5,0xde,0xcd,0xe2,0x7f,0x00,0x00,0x6f,0xd5,0xde,0xcd,0xe2,0x7f,0x00,0x00,
      0x6f,0xd5,0xde,0xcd,0xe2,0x7f,0x00,0x00 
  };
  
  boost::multiprecision::uint256_t dh_a = 0;
  for(int i = 0; i < 24; i++)
    {
      dh_a <<= 8;
      dh_a |= dh_a_temp[i];
    }

  cout << "dh_a = " << hex << dh_a << dec << endl;

  uint64_t result = create_public_key(dh_p,dh_g,dh_a);
  cout << "result = " << result << endl;
  cout << "Diffie hellman" << endl;


}
