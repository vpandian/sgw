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

uint8_t SK_ai[20];
uint8_t SK_ar[20];
uint8_t SK_ei[16];
uint8_t SK_er[16];


uint8_t i_auth[20];
uint8_t r_auth[20];
uint8_t i_enc[16];
uint8_t r_enc[16];


const uint8_t IPAD = 0x36;
const uint8_t OPAD = 0x5C;

#define PORT 500

#define BUFLEN 4096

#pragma pack(1)

char ip_str[] = "192.168.1.13";
//char ip_str[] = "192.168.244.148";

Integer dh_p("0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF");

// dh_g is the g
Integer dh_g("0x02");

// I think it is a private key. (g^a) mod p
Integer dh_a("0x6FD5DECDE27F00006FD5DECDE27F00006FD5DECDE27F0000");
Integer shared_key;
Integer public_key;
using namespace std;

typedef struct isakmp_hdr_s
{
  //uint8_t initiator_cookie[8];
  //uint8_t responder_cookie[8];
  uint64_t initiator_cookie;
  uint64_t responder_cookie;
  uint8_t next_payload;
  uint8_t version;
  uint8_t exchange_type;
  uint8_t flags;
  uint32_t message_id;
  uint32_t length;
}isakmp_hdr_t;

typedef struct isakmp_sa_hdr_s
{
  uint8_t next_payload;
  uint8_t critical_bit;
  uint16_t payload_length;
}isakmp_sa_hdr_t,isakmp_nonce_hdr_t,isakmp_encrypted_hdr_t,isakmp_common_hdr_t;

typedef struct isakmp_transform_hdr_s
{
  uint8_t next_payload;
  uint8_t critical;
  uint16_t payload_length;
  uint8_t transform_type;
  uint8_t reserved;
  uint16_t transform_id;
}isakmp_transform_hdr_t;

typedef struct isakmp_proposal_hdr_s
{
  uint8_t next_payload;
  uint8_t critical;
  uint16_t payload_length;
  uint8_t proposal_number;
  uint8_t protocol_id;
  uint8_t spi_size;
  uint8_t num_transforms;
}isakmp_proposal_hdr_t;

typedef struct isakmp_transform_atr_s
{
  uint16_t attribute_flag_type;
  uint16_t attribute_value;

}isakmp_transform_atr_t;

typedef struct isakmp_notify_hdr_s
{
  uint8_t next_payload;
  uint8_t critical_bit;
  uint16_t payload_length;
  uint8_t protocol_id;
  uint8_t spi_size;
  uint16_t notify_message_type;
}isakmp_notify_hdr_t;

typedef struct isakmp_identification_hdr_s
{
  uint8_t next_payload;
  uint8_t critical_bit;
  uint16_t payload_length;
  uint8_t id_type;
  uint8_t protocol_id;
  uint16_t port;
}isakmp_identification_hdr_t;

typedef struct isakmp_certificate_request_hdr_s
{
  uint8_t next_payload;
  uint8_t critical_bit;
  uint16_t payload_length;
  uint8_t certificate_type;
}isakmp_certificate_request_hdr_t;

typedef struct isakmp_configuration_hdr_s
{
  uint8_t next_payload;
  uint8_t critical_bit;
  uint16_t payload_length;
  uint8_t type;
}isakmp_configuration_hdr_t;

typedef struct isakmp_traffic_selector_hdr_s
{
  uint8_t next_payload;
  uint8_t critical_bit;
  uint16_t payload_length;
  uint8_t type;
  uint8_t res;
  uint16_t res1;
}isakmp_traffic_selector_hdr_t;


typedef struct isakmp_ke_hdr_s
{
  uint8_t next_payload;
  uint8_t critical_bit;
  uint16_t payload_length;
  uint16_t dh_group;
  uint16_t reserved;
}isakmp_ke_hdr_t;

union payload
{
  isakmp_sa_hdr_t sah;
  isakmp_encrypted_hdr_t ench;
  isakmp_nonce_hdr_t nonceh;
  isakmp_notify_hdr_t notifyh;
  isakmp_identification_hdr_t idenh;
  isakmp_configuration_hdr_t configh;
  isakmp_certificate_request_hdr_t certh;
  isakmp_traffic_selector_hdr_t trafh;
  isakmp_ke_hdr_t keh;
};

enum ePayloadType_t
{
  eNoNextPayload = 0,
  eSecurityAssociation = 33,
  eKeyExchange = 34,
  eIdentificationInitiator = 35,
  eIdentificationResponder = 36,
  eCertificateCERT	= 37,
  eCertificateRequest = 38,
  eAuthentication = 39,
  eNonce = 40,
  eNotify = 41,
  eDelete = 42,
  eVendorID = 43,
  eTrafficSelectorInitiator = 44,
  eTrafficSelectorResponder = 45,
  eEncryptedandAuthenticated = 46,
  eConfiguration = 47,
  eExtensibleAuthentication = 48,
  eGenericSecurePasswordMethod = 49,
  eGroupIdentification = 50,
  eGroupSecurityAssociation = 51,
  eKeyDownload = 52,
  eEncryptedandAuthenticatedFragment = 53,
};

enum eNotifyMessageStatusTypes
{
  eCookie = 16390,
};

const uint8_t cFlags_I = 1 << 3;
const uint8_t cFlags_V = 1 << 4;
const uint8_t cFlags_R = 1 << 5;
const uint8_t cCritical_Y = 1 << 7;
const uint8_t cCritical_N = 0;
const uint8_t cCookieLen = 20;

enum eEndPointState
  {
    eEPInit = 0,
  };

class endpoint
{
public:
  uint64_t iSPI;
  uint64_t rSPI;
  eEndPointState eps;
  uint32_t message_id;
  bool proposal_supported;
  uint8_t dh_key[2048];
  uint8_t dh_group;
  uint16_t dh_key_bytes;
  uint8_t nonce_i[256];
  uint8_t num_nonce_i_bytes;
  uint8_t nonce_r[16];
  endpoint(uint64_t _iSPI, uint64_t _rSPI)
  {
    iSPI = _iSPI;
    rSPI = _rSPI;
    eps = eEPInit;
    dh_group = 0;
    dh_key_bytes = 0;
    num_nonce_i_bytes = 0;
    proposal_supported = false;
  }

  void recv(uint8_t * buf, int len, int fd);
  void doCalculation();
  void hasher(uint8_t pad, uint8_t * seed,uint8_t seed_len,uint32_t * hash);
};

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

  cout << "iSPI = " << hex << be64toh(iSPI) << dec << endl;
  cout << "rSPI = " << hex << be64toh(rSPI) << dec << endl;
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
  memcpy(S2+num_nonce_i_bytes + 16 +8, &rSPI,8);
  S2[num_nonce_i_bytes + 16 + 8 + 8] = 0x01;
  prf(SKSEED,S2,num_nonce_i_bytes + 16 + 8 + 8+1, T1);
  cout << "T1 = " << hex << htonl(T1[0]) << htonl(T1[1]) << htonl(T1[2]) << htonl(T1[3]) << htonl(T1[4]) << dec << endl;
  
  // Now T2
  memcpy(S1,T1,20);
  S2[num_nonce_i_bytes + 16 + 8 + 8] = 0x02;
  prf(SKSEED,S1,num_nonce_i_bytes + 16 + 8 + 8+1+20, T2);
  memcpy(SK_ai,T2,20);

  cout << "T2 (SK_ai) = " << hex << htonl(T2[0]) << htonl(T2[1]) << htonl(T2[2]) << htonl(T2[3]) << htonl(T2[4]) << dec << endl;
  

  // Now T3
  memcpy(S1,T2,20);
  S2[num_nonce_i_bytes + 16 + 8 + 8] = 0x03;
  prf(SKSEED,S1,num_nonce_i_bytes + 16 + 8 + 8+1+20, T3);
  memcpy(SK_ar,T3,20);
  cout << "T3 = (SK_ar) " << hex << htonl(T3[0]) << htonl(T3[1]) << htonl(T3[2]) << htonl(T3[3]) << htonl(T3[4]) << dec << endl;
  
  // Now T4
  memcpy(S1,T3,20);
  S2[num_nonce_i_bytes + 16 + 8 + 8] = 0x04;
  prf(SKSEED,S1,num_nonce_i_bytes + 16 + 8 + 8+1+20, T4);
  memcpy(SK_ei,T4,16);
  memcpy(SK_er,T4+4,4);
  cout << "T4 = (SK_ei) + 4-bytes if SK_er " << hex << htonl(T4[0]) << htonl(T4[1]) << htonl(T4[2]) << htonl(T4[3]) << htonl(T4[4]) << dec << endl;
  
  // Now T5
  memcpy(S1,T4,20);
  S2[num_nonce_i_bytes + 16 + 8 + 8] = 0x05;
  prf(SKSEED,S1,num_nonce_i_bytes + 16 + 8 + 8+1+20, T5);
  memcpy(SK_er+4,T5,12);
  cout << "T5 = (remaining 12-bytes of SK_er) " << hex << htonl(T5[0]) << htonl(T5[1]) << htonl(T5[2]) << htonl(T5[3]) << htonl(T5[4]) << dec << endl;
  
  // Now T6
  memcpy(S1,T5,20);
  S2[num_nonce_i_bytes + 16 + 8 + 8] = 0x06;
  prf(SKSEED,S1,num_nonce_i_bytes + 16 + 8 + 8+1+20, T6);
  cout << "T6 = " << hex << htonl(T6[0]) << htonl(T6[1]) << htonl(T6[2]) << htonl(T6[3]) << htonl(T6[4]) << dec << endl;

  // Now T7
  memcpy(S1,T6,20);
  S2[num_nonce_i_bytes + 16 + 8 + 8] = 0x07;
  prf(SKSEED,S1,num_nonce_i_bytes + 16 + 8 + 8+1+20, T7);
  cout << "T7 = " << hex << htonl(T7[0]) << htonl(T7[1]) << htonl(T7[2]) << htonl(T7[3]) << htonl(T7[4]) << dec << endl;

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

  //T2 = prf (K, T1 | S | 0x02)

}


enum eTranformType
  {
    eENCR = 1,
    ePRF = 2,
    eINTEG = 3,
    eD_H = 4,
  };
enum eENCR_ID
  {
    eENCR_AES_CBC= 12,
  };
enum ePRF_ID
  {
    ePRF_HMAC_SHA1 = 2,
  };
enum eINTEG_ID
  {
    eAUTH_HMAC_SHA1_96 = 2,
  };
enum eD_H_ID
  {
    eDH_1024_MODP = 2,
    eDH_2048_MODP = 14,
  };

class parser
{
public:
  bool cookie_checker(uint8_t * data, int len, uint8_t next_payload);
  uint32_t generate_cookie_response(uint8_t * isakmph, int len);
  void parse_main(uint8_t * data, int len, endpoint * ep, uint8_t next_payload);
  static void parse_notify(uint8_t * data, int len, endpoint * ep);
  static void parse_sa(uint8_t * data, int len, endpoint * ep);
  static void parse_key_exchange(uint8_t * data, int len, endpoint * ep);
  static void parse_nonce(uint8_t * data, int len, endpoint * ep);
};

void parse_none(uint8_t * data, int len, endpoint * ep)
{
  cout << "Parse none called" << endl;
}

void parser::parse_nonce(uint8_t * data, int len, endpoint * ep)
{
  cout << "In nonce parser" << endl;
  isakmp_nonce_hdr_t * nonceh = ((isakmp_nonce_hdr_t *)data);

  ep->num_nonce_i_bytes = ntohs(nonceh->payload_length)-sizeof(isakmp_nonce_hdr_t);
  memcpy(ep->nonce_i,(uint8_t *)(nonceh+1),ep->num_nonce_i_bytes);
  for(int i = 0;i < ep->num_nonce_i_bytes;i++)
    {
      cout << hex << setw(2) << setfill('0') << (uint32_t)ep->nonce_i[i] << dec << " ";
      if((i+1)%16 == 0)
	{
	  cout << endl;
	}
    }
  cout << endl;
}

void parser::parse_key_exchange(uint8_t * data, int len, endpoint * ep)
{
  cout << "In key exchange parser" << endl;
  isakmp_ke_hdr_t * keh = ((isakmp_ke_hdr_t *)data);
  ep->dh_key_bytes = ntohs(keh->payload_length)-sizeof(isakmp_ke_hdr_t);
  memcpy(ep->dh_key,(uint8_t *)(keh+1),ep->dh_key_bytes);
  ep->dh_group = keh->dh_group;
  for(int i = 0;i < ep->dh_key_bytes;i++)
    {
      cout << hex << setw(2) << setfill('0') << (uint32_t)ep->dh_key[i] << dec << " ";
      if((i+1)%16 == 0)
	{
	  cout << endl;
	}
    }
  public_key = ModularExponentiation(dh_g, dh_a, dh_p);
  cout << "our public key = " << hex << public_key << dec << endl;
  cout << endl;
#if 0
  stringstream str1;
  str1 << "0x";
  for(int i = 0; i < ep->dh_key_bytes ; i++)
    {
      cout << hex << (uint16_t) ep->dh_key[i] << dec;
      str1 << hex << setw(2) << setfill('0')<< (uint16_t)ep->dh_key[i] << dec;
    }
  cout << endl;
  cout << str1.str().c_str() << endl;
  Integer dh_public_key(str1.str().c_str()); 

  shared_key = ModularExponentiation(dh_public_key, dh_a, dh_p);
  cout << "shared key = " << hex << shared_key << dec << endl;
  cout << endl;
#endif
}

void parser::parse_sa(uint8_t * data, int len, endpoint * ep)
{
  cout << "In SA parser" << endl;
  isakmp_sa_hdr_t * sah = ((isakmp_sa_hdr_t *)data);
  uint16_t sal = ntohs(sah->payload_length) - sizeof(isakmp_sa_hdr_t);
  isakmp_proposal_hdr_t * proph = (isakmp_proposal_hdr_t *)(sah + 1);
  uint8_t next_payload = 0;
  do
    {
      cout << "proposal number = " << (uint32_t)proph->proposal_number<< endl;
      cout << "number of transforms = " << (uint32_t)proph->num_transforms << endl;
      next_payload = proph->next_payload;
      
      isakmp_transform_hdr_t * transh = (isakmp_transform_hdr_t *)(proph + 1);
      bool is_enc = false;
      bool is_prf = false;
      bool is_integ = false;
      bool is_dh = false;
      
      for(int i=0;i<proph->num_transforms;i++)
	{
	  cout << "transform type = " << (uint32_t)transh->transform_type << endl;
	  cout << "transform id = " << ntohs(transh->transform_id) << endl;
	  switch(transh->transform_type)
	    {
	    case eENCR:
	      if(ntohs(transh->transform_id) == eENCR_AES_CBC)
		{
		  is_enc = true;
		}
	      break;
	    case ePRF:
	      if(ntohs(transh->transform_id) == ePRF_HMAC_SHA1)
		{
		  is_prf = true;
		}
	      break;
	    case eINTEG:
	      if(ntohs(transh->transform_id) == eAUTH_HMAC_SHA1_96)
		{
		  is_integ = true;
		}
	      break;
	    case eD_H:
	      if(ntohs(transh->transform_id) == eDH_2048_MODP)
		{
		  is_dh = true;
		}
	      break;
	    default:
	      cout << "unknown transform type = " << (uint32_t)transh->transform_type<< endl;
	      break;
	    }
	  transh = (isakmp_transform_hdr_t *)(((uint8_t *)transh) + ntohs(transh->payload_length));
	}
      if (is_enc && is_prf && is_integ && is_dh)
	{
	  // update in endpoint object and return
	  cout << "Got the proposal supported by me" << endl;
	  ep->proposal_supported = true;
	  return;
	}

      proph = (isakmp_proposal_hdr_t *)(((uint8_t *)proph) + ntohs(proph->payload_length));

      
    }while(next_payload != eNoNextPayload);
  cout << "parse sa - we should never reach here" << endl;
  
  
  exit(1);
}

void parser::parse_notify(uint8_t * data, int len, endpoint * ep)
{
  cout << "In notify parser" << endl;
  union payload * pl;
  isakmp_notify_hdr_t * notifyh = ((isakmp_notify_hdr_t *)data);
  if(ntohs(notifyh->notify_message_type) == eCookie)
    {
      cout << "cookie is there" << endl;
      if(!strncmp((char *)(notifyh+1),"anbu is the mass guy", 20))
	{
	  cout << "It is our cookie, cookie validation succeeded" << endl;
	}
      else
	{
	  cout << "It is not our cookie, cookie validation not succeeded" << endl;
	}
    }
  else
    {
      cout << "other notify:cookie is not present in the notify" << endl;
    }
  
}


void (*parser_code[256]) (uint8_t *, int,endpoint *) =
{
  parse_none, // 0
  parse_none, // 1
  parse_none, // 2
  parse_none, // 3
  parse_none, // 4
  parse_none, // 5
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none, // 10
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none, // 20
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parser::parse_sa, //33
  parser::parse_key_exchange,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parser::parse_nonce,
  parser::parse_notify, //41
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none,
  parse_none
};

// parse the whole packet and store the necessary information in the object.
// Individual functions for parsing each payload
// parser_main(rescurive) controls the whole parser mechanishm
void parser::parse_main(uint8_t * data, int len, endpoint * ep, uint8_t next_payload)
{

  cout << "In parser function" << endl;
  cout << "next payload = " << (uint32_t)next_payload << endl;

  if(next_payload == eNoNextPayload)
    {
      cout << "I think it parsed the packet completely" << endl;
      return;
    }
  
  // Noe look at the array and call tha appropriate function for parsing. This avoids the switch case logic.
  (*parser_code[next_payload])(data,len,ep);

  isakmp_common_hdr_t * common = (isakmp_common_hdr_t *)data;
  cout << "next = " << (uint32_t)common->next_payload << endl;
  cout << "next = " << (uint32_t)ntohs(common->payload_length)<< endl;
  return parse_main(data+ntohs(common->payload_length), len-ntohs(common->payload_length), ep, common->next_payload);

  //foo = &parse_notify;
  //(*foo)(data,len,ep);
  
  exit(1);
}

uint32_t parser::generate_cookie_response(uint8_t * data, int len)
{
  isakmp_hdr_t * isakmph;
  isakmph = ((isakmp_hdr_t *)data);
  cout << "In generate cookie response section" << endl;
  cout << "isakmph = " << hex << isakmph << dec << endl;
  cout << "isakmph + 1 = " << hex << isakmph+1 << dec << endl;
    
  isakmp_notify_hdr_t * noti = (isakmp_notify_hdr_t *) (isakmph + 1);
  cout << "noti = " << hex << noti << dec << endl;
  cout << "noti + 1 = " << hex << noti+1 << dec << endl;

  memset(noti,0,sizeof(isakmp_notify_hdr_t));
  strcpy((char *)(noti+1),"anbu is the mass guy");
  cout << "noti->next_payload = " << hex << &(noti->next_payload) << dec << endl;
  cout << "noti->payload_length = " << hex << &(noti->payload_length) << dec << endl;
  noti->next_payload = eNoNextPayload;
  noti->critical_bit = cCritical_N;
  uint16_t pl = sizeof(isakmp_notify_hdr_t) + cCookieLen;
  noti->payload_length = htons(pl);
  noti->protocol_id = 0;
  noti->spi_size = 0;
  noti->notify_message_type = htons(eCookie);

  
  isakmph->next_payload = eNotify;
  isakmph->flags = cFlags_R;
  uint32_t l = sizeof(isakmp_hdr_t) + pl;
  isakmph->length = htonl(l);
  
  return(ntohl(isakmph->length));
  
}

bool parser::cookie_checker(uint8_t * data, int len, uint8_t next_payload)
{
  if(next_payload == eNotify)
    {
      isakmp_notify_hdr_t * noti = (isakmp_notify_hdr_t *)data;
      if(ntohs(noti->notify_message_type) == eCookie)
	{
	  return true;
	}
    }
  else if(next_payload == eNoNextPayload)
    {
      return false;
    }
  isakmp_common_hdr_t * common = (isakmp_common_hdr_t *)data;
  return cookie_checker(data+ntohs(common->payload_length), len-ntohs(common->payload_length), common->next_payload);
}
parser p;



void packet_parser(uint8_t * data, int len)
{
  // See the responder spi and make decision about the session
  isakmp_hdr_t isakmph;
  isakmph = *((isakmp_hdr_t *)data);
  cout << hex << be64toh(isakmph.initiator_cookie) << dec << endl;
  cout << hex << be64toh(isakmph.responder_cookie) << dec << endl;
  cout << "Next payload = " << (uint32_t)isakmph.next_payload << endl;
  uint32_t next_packet = (uint32_t)isakmph.next_payload;
  data += sizeof(isakmp_hdr_t);
  
  while(1)
    {
      switch (next_packet)
	{
	case 0x21:
	  cout << "Next packet is security association " << endl;
	  union payload pl;
	  pl.sah = *((isakmp_sa_hdr_t *)data);
	  cout  <<  "payload length - " << ntohs(pl.sah.payload_length) << endl;
	  next_packet = (uint32_t)pl.sah.next_payload;
	  cout  <<  "Next payload - " << next_packet << endl;
	  data += ntohs(pl.sah.payload_length);
	  break;
	case 0x22:
	  cout << "It is a key exchange packet da saami" << endl;
	  pl.keh = *((isakmp_ke_hdr_t *)data);
	  cout  <<  "payload length - " << ntohs(pl.keh.payload_length) << endl;
	  cout  <<  "reserved - " << hex << ntohs(pl.keh.reserved) << dec<< endl;
	  cout  <<  "gh - " << hex <<ntohs(pl.keh.dh_group) << dec<< endl;
	  next_packet = (uint32_t)pl.keh.next_payload;
	  cout  <<  "Next payload - " << next_packet << endl;

	  data += ntohs(pl.sah.payload_length);
	  break;
	case 0x26:
	  cout << "It is a certificate request" << endl;
	  pl.certh = *((isakmp_certificate_request_hdr_t *)data);
	  cout  <<  "payload length - " << ntohs(pl.certh.payload_length) << endl;
	  next_packet = (uint32_t)pl.certh.next_payload;
	  cout << "Next Packet = "<< hex << next_packet<< dec << endl;
	  //parse_notify_payload(memblock, ntohs(pl.notifyh.payload_length));
	  data += ntohs(pl.certh.payload_length);
	  break;

	case 0x28:
	  cout << "It is a nonce  packet" << endl;
	  pl.nonceh = *((isakmp_nonce_hdr_t *)data);
	  cout << "Payload length : " << hex << ntohs(pl.nonceh.payload_length) << dec << endl;
	  next_packet = (uint32_t)pl.nonceh.next_payload;
	  cout << "Pasy load length = " << ntohs(pl.nonceh.payload_length) << endl;
	  data += ntohs(pl.nonceh.payload_length);
	  break;
	case 0x29:
	  cout << "It is a Notify  packet" << endl;
	  pl.notifyh = *((isakmp_notify_hdr_t *)data);
	  cout << "Payload length : " << hex << ntohs(pl.notifyh.payload_length) << dec << endl;
	  next_packet = (uint32_t)pl.notifyh.next_payload;
	  cout << "Next Packet = "<< hex << (uint32_t)(pl.notifyh.next_payload)<< dec << endl;
	  data += ntohs(pl.notifyh.payload_length);
	  break;
	default:
	  cout << "In default case" << endl;
	  cout << "Next packet = " << (uint32_t)next_packet << endl;
	  next_packet = 0;
	  break;
	}
      if(next_packet == 0)
	{
	  break;
	}
    }
}

uint32_t packet_builder(uint8_t * data, int len, endpoint * ep)
{
  cout << "In packet builder" << endl;
  isakmp_hdr_t * isakmph;
  isakmph = ((isakmp_hdr_t *)data);

#if 0
  // build the sa header. We know that the Thaere is an extra notify header in the old packet
  
  isakmp_notify_hdr_t * notih = (isakmp_notify_hdr_t *)(isakmph + 1);
  cout << (uint32_t)ntohs(notih->payload_length) << endl;
  int new_len = len - sizeof(isakmp_hdr_t) - ntohs(notih->payload_length);
  cout << "len = " << len << endl;
  cout << "len = " << new_len << endl;
  memcpy(data+sizeof(isakmp_hdr_t), data+sizeof(isakmp_hdr_t)+ntohs(notih->payload_length),new_len);
  isakmp_sa_hdr_t * sah = (isakmp_sa_hdr_t *)(isakmph + 1);
  cout << "sa payload length = " << (uint32_t)ntohs(sah->payload_length) << endl;
  
  
  
  exit(1);
#endif

  // build sa
  isakmp_sa_hdr_t * sah = (isakmp_sa_hdr_t *)(isakmph + 1);
  memset(sah,0,sizeof(isakmp_sa_hdr_t));
  sah->next_payload = eKeyExchange;   
  // critical bit in sa is set to 0


  // now concentrate on the proposal structure
  isakmp_proposal_hdr_t * proph = (isakmp_proposal_hdr_t *)(sah+1);
  memset(proph,0,sizeof(isakmp_proposal_hdr_t));
  // proposal length is set at the end

  proph->proposal_number = 0x01;
  proph->protocol_id = 0x01;
  proph->num_transforms = 0x04;
  proph->next_payload = eNoNextPayload;

  // now focus on the transform
  isakmp_transform_hdr_t * transh = (isakmp_transform_hdr_t *)(proph+1);
  memset(transh,0,sizeof(isakmp_transform_hdr_t));
  transh->next_payload = 0x03; // next payload is also transform 
  transh->transform_type = eENCR;
  transh->transform_id = htons(eENCR_AES_CBC);

  // add tranform attribute. after the transform header
  isakmp_transform_atr_t * trans_atr_h = (isakmp_transform_atr_t *)(transh+1);
  uint16_t ft = 1 << 15 | 14; // need an enum for key_len
  trans_atr_h->attribute_flag_type = htons(ft);
  trans_atr_h->attribute_value = htons(128);
  
  // add transform length
  uint16_t payload_length = sizeof(isakmp_transform_hdr_t) + sizeof(isakmp_transform_atr_t);
  transh->payload_length = htons(payload_length);

  // build the second transform
  transh = (isakmp_transform_hdr_t *)(trans_atr_h+1);
  memset(transh,0,sizeof(isakmp_transform_hdr_t));
  transh->next_payload = 0x03; // next payload is also transform
  transh->transform_type = ePRF;
  transh->transform_id = htons(ePRF_HMAC_SHA1);
  payload_length += sizeof(isakmp_transform_hdr_t);
  transh->payload_length = htons(sizeof(isakmp_transform_hdr_t));
  
  transh +=1;
  memset(transh,0,sizeof(isakmp_transform_hdr_t));
  transh->next_payload = 0x03; // next payload is also transform
  transh->transform_type = eINTEG;
  transh->transform_id = htons(eAUTH_HMAC_SHA1_96);
  payload_length += sizeof(isakmp_transform_hdr_t);
  transh->payload_length = htons(sizeof(isakmp_transform_hdr_t));

  transh +=1;
  memset(transh,0,sizeof(isakmp_transform_hdr_t));
  transh->next_payload = 0x03; // next payload is also transform
  transh->transform_type = eD_H;
  transh->transform_id = htons(eDH_1024_MODP);
  payload_length += sizeof(isakmp_transform_hdr_t);
  transh->payload_length = htons(sizeof(isakmp_transform_hdr_t));

  sah->payload_length = htons(payload_length+sizeof(isakmp_sa_hdr_t)+sizeof(isakmp_proposal_hdr_t));
  proph->payload_length = htons(payload_length+sizeof(isakmp_proposal_hdr_t));
  cout << "sa payload length = " << hex << (uint32_t)ntohs(sah->payload_length) << dec << endl;

  // build key exchange
  isakmp_ke_hdr_t * keh = (isakmp_ke_hdr_t *)(transh+1);
  memset(keh,0,sizeof(isakmp_ke_hdr_t));
  keh->next_payload = eNonce;
  keh->dh_group = htons(0x02);// we need enum for this
  uint8_t * key_val_ptr = (uint8_t *)(keh+1);
  for (int i=0;i<public_key.ByteCount();i++)      
    key_val_ptr[public_key.ByteCount()-1-i]=public_key.GetByte(i); 
  keh->payload_length = htons(sizeof(isakmp_ke_hdr_t)+public_key.ByteCount());
  
  // build nonce
  isakmp_nonce_hdr_t * nonceh = (isakmp_nonce_hdr_t *)(key_val_ptr+public_key.ByteCount());
  memset(nonceh,0,sizeof(isakmp_nonce_hdr_t));
  nonceh->next_payload = eNoNextPayload;
  memcpy((uint8_t *)(nonceh+1),"1234567890123456",16);
  memcpy((uint8_t *)(ep->nonce_r),"1234567890123456",16);
  
  nonceh->payload_length = htons(sizeof(isakmp_nonce_hdr_t)+16);
  
  isakmph->responder_cookie = be64toh(0x01);
  isakmph->next_payload = eSecurityAssociation;
  isakmph->flags = cFlags_R;
  uint32_t l = sizeof(isakmp_hdr_t) + ntohs(sah->payload_length) + ntohs(keh->payload_length)+ ntohs(nonceh->payload_length);
  isakmph->length = htonl(l);
  return l;

}


void just_send(uint8_t * buf, int len, int fd)
{
  struct sockaddr_in si_other;
  int s, i, slen=sizeof(si_other), recv_len;
  #if 0
  if ( (s=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
    {
      cout << "socket creation problem" << endl;
    }
  #endif
  memset((char *) &si_other, 0, sizeof(si_other));
  si_other.sin_family = AF_INET;
  si_other.sin_port = htons(500);
  if (inet_aton(ip_str , &si_other.sin_addr) == 0)
    {
        fprintf(stderr, "inet_aton() failed\n");
        exit(1);
    }

  for(int i =0;i<len;i++)
    {
      cout << hex << " " << (uint32_t)buf[i] << dec;
      if (i%16 == 0)
	{
	  cout << endl;
	}
    }
  cout << endl;
  
//send the message                                                      
  if (sendto(fd,buf, len , 0 , (struct sockaddr *) &si_other, slen)==-1)
        {
          cout << "send problem" << endl;
        }
  cout << "sent successfully" << endl; 
}

void endpoint::recv(uint8_t * buf, int len, int fd)
{
  cout << "In endpoint recv method" << endl;

  // check if tha packet is an ISAKMP packet or not (validation)
  
  // call the parser and store the necessary information in the endpoint object
  // Assuming the packet is IAKMP packet. parse and store the information in the endoint object
  isakmp_hdr_t * isakmph;
  isakmph = ((isakmp_hdr_t *)buf);

  message_id = ntohl(isakmph->message_id);
  
  cout << hex << be64toh(isakmph->initiator_cookie) << dec << endl;
  cout << hex << be64toh(isakmph->responder_cookie) << dec << endl;
  cout << "packet size = " << len << endl;
  p.parse_main(buf+sizeof(isakmp_hdr_t),len-sizeof(isakmp_hdr_t), this, isakmph->next_payload);
  
  // set the nonce_r in the object 
  // now it is a garbage

  // form the fourth packet with the information we have in the endpoint object  and send it
  uint32_t l = packet_builder(buf,len,this);

  // send the 4th packet now
  cout << "sending len = " << l << endl;
  just_send((uint8_t *)buf, l, fd);
  
}

class sender
{
public:
  struct sockaddr_in si_other;
  int sfd;
  uint16_t port;
  uint32_t ip;
  sender(uint16_t _port,uint32_t _ip);
  int udp_send(uint8_t * buf,uint32_t len, int fd);
};

sender::sender(uint16_t _port, uint32_t _ip)
{
  if((sfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
    {
      cout << "socket creation problem" << endl;
    }
  cout << "constructor called " << port << " " << hex << ip << dec << endl;
  memset((char *) &si_other, 0, sizeof(si_other));
  si_other.sin_family = AF_INET;
  si_other.sin_port = htons(port);
  //si_other.sin_addr.s_addr = htonl(ip);

  if (inet_aton(ip_str , &si_other.sin_addr) == 0) 
    {
      fprintf(stderr, "inet_aton() failed\n");
      exit(1);
    }
  ip = _ip;
  port = _port;
}

int sender::udp_send(uint8_t * buf,uint32_t len, int lfd)
{
  struct sockaddr_in si_other;

  int slen = sizeof(si_other);
  memset((char *) &si_other, 0, sizeof(si_other));
  si_other.sin_family = AF_INET;
  si_other.sin_port = htons(port);
  //si_other.sin_addr.s_addr = htonl(ip);
  if (inet_aton(ip_str , &si_other.sin_addr) == 0) 
    {
      fprintf(stderr, "inet_aton() failed\n");
      exit(1);
    }

  //send the message
  cout << "sfd = " << sfd << endl;
  cout << "port = " << ntohs(si_other.sin_port) << endl;
  cout << "ip = " << hex << ntohl(si_other.sin_addr.s_addr)<< dec << endl;

  if (sendto(sfd, buf, len , 0 , (struct sockaddr *) &si_other, slen)==-1)
    {
      perror("Send failed: ");
      cout << "send problem" << endl;
    }
  
}

class endpoint_manager
{
  
public:
  uint64_t rSPI;
  endpoint * epdb[4096];
  endpoint_manager()
  {
    rSPI = 0;
    memset(epdb,sizeof(epdb),0);
  }
  inline uint64_t alloc_rSPI(){return ++rSPI;}
  void recv(uint16_t port, uint32_t ip_v4, uint8_t * data, int len, int fd)
  {
    // write a validator to see if the respoder SPI is present or not. If the cookie is not present then ask for cookie. dont initialize the endpoint object or increment the responder SPI yet
    // If the cookie and everything is present and if the packet comes out clean after validating then increament the responder SPI counter and intialize the endpoint object.
    // If the responder SPI is present then directly call the appropriate object or generate an error message

    // here in this packet check for the responder SPI

    isakmp_hdr_t * isakmph;
    isakmph = ((isakmp_hdr_t *)data);
    cout << hex << be64toh(isakmph->initiator_cookie) << dec << endl;
    cout << hex << be64toh(isakmph->responder_cookie) << dec << endl;
    if(be64toh(isakmph->responder_cookie) == 0)
      {
	cout << "Responder cookie is not there.. Have to validate more" << endl;
	// Check if the cookie is present in the packet or not by calling the parser
	if(!p.cookie_checker(data+sizeof(isakmp_hdr_t),len-sizeof(isakmp_hdr_t),isakmph->next_payload))
	  {
	    // call cookie generator
	    cout << "calling cookie generator as cookie is not present in the packet" << endl;
	    uint32_t l = p.generate_cookie_response(data, len);
	    //sender * s = new sender(port,ip_v4);
	    cout << "sending len = " << l << endl;
	    just_send((uint8_t *)isakmph, l, fd);

	  }
	else
	  {
	    cout << "cookie is present" << endl;
	    // assign a responder SPI
	    //endpoint * ep = new endpoint(be64toh(isakmph->initiator_cookie), alloc_rSPI());
	    endpoint * ep = new endpoint(isakmph->initiator_cookie, be64toh(alloc_rSPI()));
	    epdb[ep->rSPI] = ep;
	    cout << "stored initiator spi = " << hex << ep->iSPI << dec << endl;
	    cout << "************** ep = " << ep << endl;
	    ep->recv(data,len,fd);
	    ep->doCalculation();

	    exit(1);
    	  }
      }
    


  }
};


endpoint_manager epm;

class listener
{
protected:
  const uint32_t MAXEVENTS = 64;
  uint16_t port;
  epoll_event * events;
  int lfd, efd;
  
public:
  listener()
  {
  }

  ~listener()
  {
  }

};

class udp_listener:private listener
{
public:
  udp_listener(uint16_t _port)
  {
    port = _port;

    // create a UDP socket
    if((lfd = socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP)) == -1)
      {
	perror("cannot create server listening socket");
	exit(1);
      }
    int yes;
    if(setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
      {
	perror("Server-setsockopt() error lol!");
	exit(1);
      }

    //intialise the struct to 0
    sockaddr_in si_me;

    memset((uint8_t *) &si_me, 0, sizeof(si_me));
    
    si_me.sin_family = AF_INET;
    si_me.sin_port = htons(port);
    si_me.sin_addr.s_addr = htonl(INADDR_ANY);
    
    // bind the socket to port
    
    if(bind(lfd,(sockaddr *)&si_me, sizeof(si_me)) == -1)
      {
	perror("cannot bind");
	exit(1);
      }

    // Accept all the data
    while(true)
      {
	sockaddr_in si_other;
	int recv_len = 0;
	socklen_t s_len = sizeof(si_other);
	uint8_t buf[BUFLEN];

	if((recv_len = recvfrom(lfd,buf,BUFLEN,0,(sockaddr *) &si_other,&s_len)) == -1)
	  {
	    perror("Recv failed");
	    exit(1);
	  }
	cout << "received length = " << recv_len << " " << ntohs(si_other.sin_port) << " " << ntohl(si_other.sin_addr.s_addr)<< endl;
	epm.recv(ntohs(si_other.sin_port),ntohl(si_other.sin_addr.s_addr),buf,recv_len, lfd);

	// send cookie from port 500 to the client

	
      }
    
  }
};

class tcp_listener:private listener
{
public:
  tcp_listener(uint16_t _port) 
  {
    port = _port;

    // create a UDP socket
    if((lfd = socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP)) == -1)
      {
	perror("cannot create server listening socket");
	exit(1);
      }
    int yes;
    if(setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
      {
	perror("Server-setsockopt() error lol!");
	exit(1);
      }

    //intialise the struct to 0
    sockaddr_in si_me;

    memset((uint8_t *) &si_me, 0, sizeof(si_me));
    
    si_me.sin_family = AF_INET;
    si_me.sin_port = htons(port);
    si_me.sin_addr.s_addr = htonl(INADDR_ANY);
    
    // bind the socket to port
    
    if(bind(lfd,(sockaddr *)&si_me, sizeof(si_me)) == -1)
      {
	perror("cannot bind");
	exit(1);
      }

    // listen - for tcp only
    # if 0
    if(listen(lfd, 10) == -1)
      {
	perror("Cannot listen!");
	exit(1);
      }
    # endif
    
    events = (epoll_event *)calloc(MAXEVENTS,sizeof(epoll_event));
    if((efd = epoll_create(MAXEVENTS)) == -1)
      {
	perror("epoll create error");
	exit(1);
      }
    epoll_event ev;
    ev.events = EPOLLIN | EPOLLET;
    ev.data.fd = lfd;
  
    if (epoll_ctl(efd,EPOLL_CTL_ADD,lfd,&ev)<0)
      {
	perror("epoll create error");
	exit(1);
      }

    while(true)
      {
	int n = epoll_wait(efd, events,MAXEVENTS,-1);
	for(int i = 0; i < n;i++)
	  {

	    if(events[i].events != EPOLLIN && events[i].events != EPOLLHUP )
	      {
		cout << "event not supported value = " << hex << events[i].events << dec << endl; 
		exit(1);
	      }
	    if(lfd == events[i].data.fd)
	      {
		// It means there is new data
		cout << "Incomming connection" << endl;
		
		// Accept all the data
		while(true)
		  {
		    sockaddr_in si_other;
		    int recv_len = 0;
		    socklen_t s_len;
		    uint8_t buf[BUFLEN];
		    if((recv_len = recvfrom(events[i].data.fd,buf,BUFLEN,0,(sockaddr *) &si_other,&s_len)) == -1)
		      {
			perror("Recv failed");
			exit(1);
		      }
		    cout << "si_other port = " 
			 <<  ntohs(si_other.sin_port)
			 << " IP = " << inet_ntoa(si_other.sin_addr) << endl;
		    
		    buf[recv_len] = '\0';
		    cout << "buf = " << buf << " len = " << recv_len <<endl;
		    
		    
		  }
		exit(1);
	      }

	  }

      }

  }
  void print_port()
  {
    cout << "port = " << port << endl;
  }

};


inline void die(char * s)
{
  perror(s);
  exit(1);
}

int main(void)
{
  udp_listener ul(500);
  sockaddr_in si_me, si_other;
  uint32_t s,i, s_len = sizeof(si_other), recv_len;
  uint8_t buf[BUFLEN];

  // create a UDP socket
  if((s = socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP)) == -1)
    {
      cout << "cannot create socket" << endl;
      exit(1);
    }

  cout << "success" << endl;

  while(1)
    {
      // try to receeive data
      if((recv_len = recvfrom(s,buf,BUFLEN,0,(sockaddr *) &si_other,&s_len)) == -1)
	{
	  cout << "recv failed" << endl;
	  exit(1);
	}
      buf[recv_len] = '\0';
      cout << "buf = " << buf << " len = " << recv_len <<endl;

    }
}
