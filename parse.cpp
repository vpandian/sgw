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

#include "sgw.hpp"
#include "aes.hpp"

#include "crypto++/dh.h"
using CryptoPP::DH;
#include "crypto++/integer.h"
using CryptoPP::Integer;
#include "crypto++/nbtheory.h"
using CryptoPP::ModularExponentiation;

using namespace std;


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
  cout << "next payload = " << (uint32_t) sah->next_payload << endl;
  cout << "payload length = " << (uint32_t) ntohs(sah->payload_length) << endl;
  isakmp_proposal_hdr_t * proph = (isakmp_proposal_hdr_t *)(sah + 1);
  uint8_t next_payload = 0;
  do
    {
      next_payload = proph->next_payload;
      cout << "proph->next_payload = " << (uint32_t) next_payload << endl;
      cout << "proph->payload_length = " << (uint32_t)ntohs(proph->payload_length) << endl;
      cout << "proph->proposal_number = " << (uint32_t)proph->proposal_number<< endl;
      cout << "proph->protocol_id = " << (uint32_t)proph->protocol_id << endl;
      cout << "proph->spi_size = " << (uint32_t)proph->spi_size << endl;
      cout << "proph->num_transforms = " << (uint32_t)proph->num_transforms << endl;

      if(proph->spi_size) {
        ep->r_esp_spi = ntohl(*(proph->spi));
        cout << "r esp spi = "<< hex << ep->r_esp_spi << dec << endl;
      }
      
      isakmp_transform_hdr_t * transh = (isakmp_transform_hdr_t *)(((uint8_t *)(proph + 1)) + proph->spi_size);
      bool is_enc = false;
      bool is_prf = false;
      bool is_integ = false;
      bool is_dh = false;
      bool is_esn = false;
      
      for(int i=0;i<proph->num_transforms;i++)
	{
	  cout << "next payload  = " << (uint32_t)transh->next_payload << endl;
          cout << "payload length = " << ntohs(transh->payload_length) << endl;
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
              cout << "Found diffie hellman yay" << "\n";
	      if(ntohs(transh->transform_id) == eDH_2048_MODP || ntohs(transh->transform_id) == eDH_1024_MODP)
		{
		  is_dh = true;
		}
	      break;
              case eESN:
                cout << "ESN number" << "\n";
                is_esn = true;
                break;
              default:
	      cout << "unknown transform type = " << (uint32_t)transh->transform_type<< endl;
	      break;
	    }
	  transh = (isakmp_transform_hdr_t *)(((uint8_t *)transh) + ntohs(transh->payload_length));
	}
      //if (is_enc && is_prf && is_integ && is_dh)
      if (proph->protocol_id == eIKE && is_enc && is_integ && is_dh && is_prf)
	{
	  // update in endpoint object and return
	  cout << "IKE::Got the proposal supported by me" << endl;
	  ep->proposal_supported = true;
	  return;
	}
      else if (proph->protocol_id == eESP && is_enc && is_esn) {
	  // update in endpoint object and return
	  cout << "ESP::Got the proposal supported by me" << endl;
	  ep->proposal_supported = true;
	  return;
      }

      else {
	cout << "is_encr = " << is_enc
	     << " iss_prf = " << is_prf
	     << " is_integ = " << is_integ
	     << " is_dh = " << is_dh << endl;
      }

      proph = (isakmp_proposal_hdr_t *)(((uint8_t *)proph) + ntohs(proph->payload_length));
      //proph = (isakmp_proposal_hdr_t *)(((uint8_t *)proph) + ntohs(proph->payload_length) + proph->spi_size);
      cout << "spi size = " << (uint32_t) proph->spi_size << endl;
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

void parser::parse_encrypted(uint8_t * data, int len, endpoint * ep)
{
  cout << "In encrypted parser" << endl;
  union payload * pl;
  isakmp_encrypted_hdr_t * encryptedh = ((isakmp_encrypted_hdr_t *)data);
  cout << "next payload = " << (uint16_t)encryptedh->next_payload << endl;
  aes_128_cbc aes_object;
  uint8_t PT[65000];
  uint8_t * CT = (uint8_t *)(encryptedh +1);
  memcpy(ep->IV,encryptedh->initialization_vector,16);
  cout << "Initiliaziaton vector = ";
  for(int i =0;i<16;i++)
  {
    cout << hex << (uint16_t)ep->IV[i] << dec << " ";
  }

  aes_object.AES128_CBC_decrypt_buffer(CT,PT,ntohs(encryptedh->payload_length),ep->SK_ei,ep->IV);
  cout << "done decrypting" << endl;
  cout << "first byte of plain text = " << endl;
  for(int i =0;i<16;i++)
  {
    cout << hex << (uint16_t)PT[i] << dec << " ";
  }
  cout << endl;
  memcpy(CT,PT,ntohs(encryptedh->payload_length));
  ep->eps = eEPAuth;
}

void parser::parse_initiator_identification(uint8_t * data, int len, endpoint * ep)
{
  cout << "In initiator identification header" << endl;
  union payload * pl;
  isakmp_id_hdr_t * idh = ((isakmp_id_hdr_t *)data);
  cout << "next payload = " << (uint16_t)idh->next_payload << endl;  
  ep->IDi_length = ntohs(idh->payload_length)-sizeof(isakmp_id_hdr_t)+4;
  cout << "identifier type = " << (uint16_t)idh->id_type << endl;
  ep->IDi = (uint8_t *)malloc(ep->IDi_length);
  cout << "ep->Idi = " << ep->IDi << " ep->IDi_;ength = " << ep->IDi_length << endl;
  memcpy(ep->IDi,&idh->id_type, ep->IDi_length);
}

void parser::parse_responder_identification(uint8_t * data, int len, endpoint * ep)
{
  cout << "In responder identification header" << endl;
  union payload * pl;
  isakmp_id_hdr_t * idh = ((isakmp_id_hdr_t *)data);
  cout << "next payload = " << (uint16_t)idh->next_payload << endl;
  ep->IDr_length = ntohs(idh->payload_length)-sizeof(isakmp_id_hdr_t)+4;
  cout << "identifier type = " << (uint16_t)idh->id_type << endl;
  ep->IDr = (uint8_t *)malloc(ep->IDr_length);
  memcpy(ep->IDr,&idh->id_type, ep->IDr_length);
}

void parser::parse_authentication(uint8_t * data, int len, endpoint * ep)
{
  cout << "In parse authentication header" << endl;
  union payload * pl;
  isakmp_authentication_hdr_t * authenticationh = ((isakmp_authentication_hdr_t *)data);
  cout << "next payload = " << (uint16_t)authenticationh->next_payload << endl;
  cout << "authenctication method = " << (uint16_t)authenticationh->auth_method << endl;
  ep->authentication_method = authenticationh->auth_method;
  memcpy(ep->authentication_initiator,data+sizeof(isakmp_authentication_hdr_t),
         ntohs(authenticationh->payload_length)-sizeof(isakmp_authentication_hdr_t));
}
void parser::parse_traffic_selector_initiator(uint8_t * data, int len, endpoint * ep)
{
  cout << "In parse traffic selector initiator" << endl;
  union payload * pl;
  isakmp_traffic_selector_hdr_t * tsh = ((isakmp_traffic_selector_hdr_t *)data);
  cout << "next payload = " << (uint16_t)tsh->next_payload << endl;
  cout << "traffic selector type = " << (uint16_t)tsh->type<< endl;
  ep->initiator_ts = (isakmp_traffic_selector_hdr_t *)malloc(ntohs(tsh->payload_length));
  memcpy(ep->initiator_ts,data,ntohs(tsh->payload_length));
}
void parser::parse_traffic_selector_responder(uint8_t * data, int len, endpoint * ep)
{
  cout << "In parse traffic selector responder" << endl;
  isakmp_traffic_selector_hdr_t * tsh = ((isakmp_traffic_selector_hdr_t *)data);
  cout << "next payload = " << (uint16_t)tsh->next_payload << endl;
  cout << "traffic selector type = " << (uint16_t)tsh->type<< endl;
  ep->responder_ts = (isakmp_traffic_selector_hdr_t *)malloc(ntohs(tsh->payload_length));
  memcpy(ep->responder_ts,data,ntohs(tsh->payload_length));
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
  parser::parse_initiator_identification,
  parser::parse_responder_identification,
  parse_none,
  parse_none,
  parser::parse_authentication,
  parser::parse_nonce,
  parser::parse_notify, //41
  parse_none,
  parse_none,
  parser::parse_traffic_selector_initiator, //44
  parser::parse_traffic_selector_responder, //45
  parser::parse_encrypted, //46
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
  cout << "next payload = " << (uint32_t)common->next_payload << endl;
  cout << "payload length = " << (uint32_t)ntohs(common->payload_length)<< endl;

  uint16_t move_header_length = ntohs(common->payload_length);
  if(next_payload == eEncryptedandAuthenticated)
  {
    move_header_length = sizeof(isakmp_encrypted_hdr_t);
  }

  return parse_main(data+move_header_length, len-move_header_length, ep, common->next_payload);

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
