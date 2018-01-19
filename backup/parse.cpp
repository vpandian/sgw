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
