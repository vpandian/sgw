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
#include "aes.hpp"

#include "sgw.hpp"
parser p;

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

uint32_t auth_packet_builder(uint8_t * data, int len, endpoint * ep)
{
  uint16_t payload_length = 0;
  cout << "Auth packet builder" << "\n";
  isakmp_hdr_t * isakmph;
  isakmph = ((isakmp_hdr_t *)data);
  isakmph->flags = cFlags_R;  
  // change packet length 
  isakmp_encrypted_hdr_t * encrh = (isakmp_encrypted_hdr_t *)(data + sizeof(isakmp_hdr_t));
  encrh->next_payload = eIdentificationResponder;
  //change the header length for encrh
  payload_length += sizeof(isakmp_encrypted_hdr_t);
  


  // build responder identification header
  isakmp_id_hdr_t * idrh = (isakmp_id_hdr_t *)(encrh+1);
  memset(idrh,0,sizeof(isakmp_identification_hdr_t));
  idrh->next_payload = eAuthentication;
  // put the responder identication data
  memcpy(&idrh->id_type, ep->IDr, ep->IDr_length);
  idrh->payload_length = htons(ep->IDr_length + sizeof(isakmp_id_hdr_t) - 4);
  cout <<"identification payload length = " << ep->IDr_length + sizeof(isakmp_id_hdr_t) - 4 << endl;
  payload_length += ntohs(idrh->payload_length);
  
  // build authentication payload header
  isakmp_authentication_hdr_t * authenticationh = (isakmp_authentication_hdr_t *)
      (((uint8_t *)(idrh))+ntohs(idrh->payload_length));
  memset(authenticationh,0,sizeof(isakmp_authentication_hdr_t));
  authenticationh->next_payload = eSecurityAssociation;
  authenticationh->auth_method = ep->authentication_method;
  // build authentication payload data
  uint32_t T[5];
  ep->generate_authentication((uint8_t *)T,false);
  memcpy((uint8_t *)(authenticationh+1),T,20);
  authenticationh->payload_length = htons(sizeof(isakmp_authentication_hdr_t) + 20);
  payload_length += ntohs(authenticationh->payload_length);
  //build sa header
  isakmp_sa_hdr_t * sah = (isakmp_sa_hdr_t *)
      (((uint8_t *)(authenticationh)) + sizeof(isakmp_authentication_hdr_t)+20);
  memset(sah,0,sizeof(isakmp_sa_hdr_t));
  sah->next_payload = eTrafficSelectorInitiator;
  
  // now concentrate on the proposal structure
  isakmp_proposal_hdr_t * proph = (isakmp_proposal_hdr_t *)(sah+1);
  memset(proph,0,sizeof(isakmp_proposal_hdr_t));
  // proposal length is set at the end

  proph->proposal_number = 0x01;
  proph->protocol_id = 0x03;
  proph->num_transforms = 0x03;
  proph->next_payload = eNoNextPayload;
  proph->spi_size = 4;

  // add spi after the proposal header
  uint32_t auth_r_spi = htonl(0x80000001);
  memcpy((uint8_t *)(proph+1),&auth_r_spi,4);
  payload_length += 4; // adding spi data size
  uint16_t sa_pl = 4;
  
  // now focus on the transform
  isakmp_transform_hdr_t * transh = (isakmp_transform_hdr_t *)(((uint8_t *)(proph+1))+4);
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
  sa_pl += sizeof(isakmp_transform_hdr_t) + sizeof(isakmp_transform_atr_t);
  payload_length += sizeof(isakmp_transform_hdr_t) + sizeof(isakmp_transform_atr_t);
  transh->payload_length = htons(sizeof(isakmp_transform_hdr_t)+sizeof(isakmp_transform_atr_t));

  // build the second transform
  transh = (isakmp_transform_hdr_t *)(trans_atr_h+1);
  memset(transh,0,sizeof(isakmp_transform_hdr_t));
  transh->next_payload = 0x03; // next payload is also transform
  transh->transform_type = eINTEG;
  transh->transform_id = htons(eAUTH_HMAC_SHA1_96);
  sa_pl += sizeof(isakmp_transform_hdr_t);
  payload_length += sizeof(isakmp_transform_hdr_t);
  transh->payload_length = htons(sizeof(isakmp_transform_hdr_t));

  transh +=1;
  memset(transh,0,sizeof(isakmp_transform_hdr_t));
  transh->next_payload = eNoNextPayload; // next payload is also transform
  transh->transform_type = eESN;


  transh->transform_id = htons(0x0000); // use enumeration later
  sa_pl += sizeof(isakmp_transform_hdr_t);
  payload_length += sizeof(isakmp_transform_hdr_t);
  transh->payload_length = htons(sizeof(isakmp_transform_hdr_t));


  sah->payload_length = htons(sa_pl+sizeof(isakmp_sa_hdr_t)+sizeof(isakmp_proposal_hdr_t));
  proph->payload_length = htons(sa_pl+sizeof(isakmp_proposal_hdr_t));
  cout << "sa payload length = " << hex << (uint32_t)ntohs(sah->payload_length) << dec << endl;
  //payload_length += ntohs(sah->payload_length);
  payload_length += sizeof(isakmp_sa_hdr_t)+sizeof(isakmp_proposal_hdr_t);

  // build traffic selector
  isakmp_traffic_selector_hdr_t * tsh = ((isakmp_traffic_selector_hdr_t *)((uint8_t *)(sah)+ntohs(sah->payload_length)));
  memcpy(tsh,ep->initiator_ts,ntohs(ep->initiator_ts->payload_length));
  tsh->next_payload = eTrafficSelectorResponder;
  payload_length += ntohs(ep->initiator_ts->payload_length);
  cout << "tsh before = " << tsh << endl;

  tsh = (isakmp_traffic_selector_hdr_t *)(((uint8_t *)tsh)+ntohs(ep->initiator_ts->payload_length));
  cout << "tsh after = " << tsh << endl;

  cout << "payload length of initiator traffic selector = " << ntohs(ep->initiator_ts->payload_length) << endl;
  memcpy(tsh,ep->responder_ts,ntohs(ep->responder_ts->payload_length));
  cout << "payload length of responder traffic selector = " << ntohs(ep->responder_ts->payload_length) << endl;
  
  tsh->next_payload = eNoNextPayload;  
  payload_length += ntohs(ep->responder_ts->payload_length);
  cout << "tsh responder = " << endl;
  uint8_t * temp_tsh = (uint8_t *)tsh;
  for(int i =0;i<ntohs(ep->responder_ts->payload_length);i++)
  {
    cout << hex << setw(2) << setfill('0')<< (uint16_t)temp_tsh[i] << dec << " ";
    if((i+1)%16 ==0) cout << endl;
  }
  cout << endl;

  cout << "Payload length of the auth packet = " << payload_length << endl;

  uint16_t encr_length = payload_length-sizeof(isakmp_encrypted_hdr_t);
  
  aes_128_cbc aes_object;
  uint8_t CT[65000];
  uint8_t ST[65000];
  uint8_t * PT = (uint8_t *)(encrh +1);

  memcpy(encrh->initialization_vector,ep->IV,16);
  uint8_t pad_length = 0;
  if(encr_length%16) {
    pad_length = 16 - (encr_length%16);
    encr_length = (encr_length & 0xFFF0) + 16;
    PT[encr_length-1] = pad_length-1;
    
  }
  
  cout << "Plain text = " << endl;
  for(int i =0;i<encr_length;i++)
  {
    cout << hex << setw(2) << setfill('0') << (uint16_t)PT[i] << dec << " ";
    if((i+1)%16 ==0) cout << endl;
  }
  cout << endl;


  cout << "going to encrypt length = " << encr_length << endl;
  //aes_object.AES128_CBC_encrypt_buffer(PT,CT,32,ep->SK_er,ep->IV);
  //aes_object.AES128_CBC_encrypt_buffer(PT,CT,payload_length-sizeof(isakmp_encrypted_hdr_t),ep->SK_er,ep->IV);
  aes_object.AES128_CBC_encrypt_buffer(PT,CT,encr_length,ep->SK_er,ep->IV);
  cout << "done encrypting" << endl;
  cout << "first byte of cipher text = " << endl;
  for(int i =0;i<encr_length;i++)
  {
    cout << hex << setw(2) << setfill('0') << (uint16_t)CT[i] << dec << " ";
    if ((i+1)%16==0) cout << endl;
  }
  cout << endl;

#if 0
  cout << "Going to decrypt (unit test) " << endl;
  //aes_object.AES128_CBC_decrypt_buffer(CT,ST,32,ep->SK_er,ep->IV);
  aes_object.AES128_CBC_decrypt_buffer(CT,ST,encr_length-sizeof(isakmp_encrypted_hdr_t),ep->SK_er,ep->IV);
  cout << "done decrypting" << endl;
  cout << "first byte of ST text = " << endl;
  for(int i =0;i<48;i++)
  {
    cout << hex << (uint16_t)ST[i] << dec << " ";
    if ((i+1)%16==0) cout << endl;
  }
  cout << endl;
 #endif

  memcpy(PT,CT,encr_length);
  uint8_t * integ = PT + payload_length - sizeof(isakmp_encrypted_hdr_t);
  // calculate integrity checksum 12 bytes
  payload_length += 12+pad_length;
  encrh->payload_length = htons(payload_length);
  
  payload_length += sizeof(isakmp_hdr_t);
  isakmph->length = htonl(payload_length);
  uint32_t integrity_value[5];
  ep->generate_intergity(data,payload_length-12,(uint8_t *)integrity_value,false);
  memcpy(data+payload_length-12,integrity_value,12);

  // test code..
  uint8_t plainText[33];
  memcpy(plainText, "Single block msgSingle block ms1", 32);
  uint8_t cipherText[33];
  uint32_t lens = 32;

  cout << "plain text = 0x";
  for (int i =0; i < lens; i++)
    {
      cout << hex << setw(2) << setfill('0')<< (uint32_t)plainText[i] << dec;
      if ((i+1)%16==0) cout << endl;
    }
  cout << endl;

  aes_object.AES128_CBC_encrypt_buffer(plainText,cipherText,lens,ep->SK_er,ep->IV);

  cout << "cipher text = 0x";
  for (int i =0; i < lens; i++)
    {
      cout << hex << setw(2) << setfill('0')<< (uint32_t)cipherText[i] << dec;
    }
  cout << endl;

  aes_object.AES128_CBC_decrypt_buffer(cipherText,plainText,lens,ep->SK_er,ep->IV);
  cout << "plain text = 0x";
  for (int i =0; i < lens; i++)
    {
      cout << hex << setw(2) << setfill('0')<< (uint32_t)plainText[i] << dec;
      if ((i+1)%16==0) cout << endl;
    }
  cout << endl;

    
  
  return payload_length;
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
  transh->next_payload = eNoNextPayload; // next payload is also transform
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


void just_send(uint8_t * buf, int len, int fd, uint32_t ip_v4)
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
  si_other.sin_addr.s_addr = htonl(ip_v4);
  #if 0
  if (inet_aton(ip_str , &si_other.sin_addr) == 0)
    {
        fprintf(stderr, "inet_aton() failed\n");
        exit(1);
    }
  #endif
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
  if (sendto(fd,buf, len , 0 , (struct sockaddr *) &si_other, slen)==-1) {
    cout << "send problem" << endl;
  }
  cout << "\n\n\n\nsent successfully\n\n\n" << endl;
}

void print_hex(const char * name, uint8_t * data,uint16_t len)
{
  cout << name << ": " << hex;
  for(int i =0; i< len;i++) {
    if(i%16==0 && i!= 0) {
      cout << endl;
    }
    cout << setw(2) << setfill('0') << (uint32_t)data[i];
  }
  cout << dec << endl;

}

void endpoint::generate_authentication(uint8_t * authentication_value, bool is_initiator)
{
  /* prf(prf(Shared Secret,"Key Pad for IKEv2"), <msg octets>)

     <msg octets> =
     2nd message | Ni | prf(SK_pr,IDr') for responder
     OR
     1st messgae | Nr | prf(SK_pi,IDi') for initiator
  */
  
  /* prf(SK_pr,IDr') or  prf(SK_pi,IDi')*/
  uint8_t * sk_p;
  uint8_t * id;
  uint8_t * message;
  uint8_t * nonce;
  uint16_t id_len;
  uint16_t message_len;
  uint16_t nonce_len;
  if( is_initiator) {
    sk_p = SK_pi;
    id = IDi;
    id_len = IDi_length;
    message = IKE_SA_INIT_I;
    message_len = IKE_SA_INIT_I_BYTES;
    nonce = nonce_r;
    nonce_len = 16; // for now.. change it
  } else {
    sk_p = SK_pr;
    id = IDr;
    id_len = IDr_length;
    message = IKE_SA_INIT_R;
    message_len = IKE_SA_INIT_R_BYTES;
    nonce = nonce_i;
    nonce_len = num_nonce_i_bytes;
  }

  print_hex("sk_pi",SK_pi,20);
  print_hex("sk_pr",SK_pr,20);
  print_hex("IDi",IDi,IDi_length);
  print_hex("IDr",IDr,IDr_length);

  uint32_t T[5];
  prf((uint32_t *)sk_p,id,id_len,T);
  print_hex("prf(sk_p,ID)", (uint8_t *)T,20);
  
  uint8_t * t_buf = (uint8_t *) malloc(message_len+nonce_len+20);
  memcpy(t_buf,message,message_len);
  memcpy(t_buf+message_len,nonce,nonce_len);
  memcpy(t_buf+message_len+nonce_len,T,20);
  uint16_t t_buf_len = message_len+nonce_len+20;
  print_hex("OCTECTS",t_buf,t_buf_len);

  uint32_t T1[5];
  prf((uint32_t *)"hellohellohellohello",(uint8_t *)"Key Pad for IKEv2",strlen("Key Pad for IKEv2"),T1);
  print_hex("prf(hello,key pad)", (uint8_t *)T1,20);

  uint32_t T2[5];
  prf(T1,t_buf,t_buf_len,(uint32_t *)authentication_value);
  print_hex("final auth value", authentication_value,20);
}

bool endpoint::validate_authentication()
{
  uint32_t T[5];
  generate_authentication((uint8_t *)T,true);
  return (memcmp(T,authentication_initiator,20) == 0);
}


void endpoint::generate_intergity(uint8_t * buf, uint16_t len,
                                  uint8_t * integrity_value, bool is_initiator)
{
  uint8_t * sk_a = is_initiator ? SK_ai:SK_ar;

  cout << "len in generate integ = " << len << endl;

  prf((uint32_t *)sk_a,buf,len,(uint32_t *)integrity_value);

  print_hex("final integ value", integrity_value,20);
}

bool endpoint::validate_integrity(uint8_t * buf, uint16_t len)
{
  uint32_t T[5];
  generate_intergity(buf,len,(uint8_t *)T,true);
  print_hex("Received inegrity = ", buf+len,12);
  return (memcmp(T,buf+len,12) == 0);
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
  uint32_t ike_len = ntohl(isakmph->length);
  cout << "isakmp header payload length = " << ike_len << endl;
  if(isakmph->exchange_type == eIKE_SA_AUTH) {
    eps = eEPAuth;

    // calculate integrity checksum of the received mesage..
    // RFC 7296 section 3.14.  Encrypted Payload
    // Integrity Checksum Data is the cryptographic checksum of the
    // entire message starting with the Fixed IKE header through the Pad
    // Length.  The checksum MUST be computed over the encrypted message.
    // Its length is determined by the integrity algorithm negotiated.
    if(validate_integrity(buf,ike_len-12)) {
      cout << "Integrity check succeeded" << endl;
    } else {
      cout << "Integrity check failed" << endl;
    }
  }
  
  p.parse_main(buf+sizeof(isakmp_hdr_t),ike_len-sizeof(isakmp_hdr_t), this, isakmph->next_payload);

  // set the nonce_r in the object
  // now it is a garbage

  // form the fourth packet with the information we have in the endpoint object  and send it
  if(eps == eEPInit) {
    // save the 3rd packet in the endpoint for authentication calculation
    IKE_SA_INIT_I = (uint8_t *) malloc(len);
    IKE_SA_INIT_I_BYTES = len;
    memcpy(IKE_SA_INIT_I,buf,len);
    
    uint32_t l = packet_builder(buf,len,this);
    // send the 4th packet now
    cout << "sending len = " << l << endl;
    just_send((uint8_t *)buf, l, fd,ip_v4);

    // save the 4th packet in the endpoint for authentication calculation
    IKE_SA_INIT_R = (uint8_t *) malloc(l);
    IKE_SA_INIT_R_BYTES = l;
    memcpy(IKE_SA_INIT_R,buf,l);
    
  } else if (eps == eEPAuth) {
    // validate authentication
    if(validate_authentication()) {
      cout << "validation succeded" << endl;
    }
    
    uint32_t l = auth_packet_builder(buf,len,this);
    // send auth packet
    cout << "Sending auth response packet" << endl;
    uint32_t auth_packet_length = auth_packet_builder(buf,len,this);
    just_send((uint8_t *)buf,auth_packet_length,fd,ip_v4);
  }

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
    // If the responder SPI is present then directly call the appropriate object or geepnerate an error message

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
	    just_send((uint8_t *)isakmph, l, fd, ip_v4);

	  }
	else
	  {
	    cout << "cookie is present" << endl;
	    // assign a responder SPI
	    //endpoint * ep = new endpoint(be64toh(isakmph->initiator_cookie), alloc_rSPI());
	    endpoint * ep = new endpoint(isakmph->initiator_cookie, be64toh(alloc_rSPI()), ip_v4);
	    ep->rSPI = rSPI;
	    epdb[ep->rSPI] = ep;
	    cout << "************** ep = " << ep << endl;
	    ep->recv(data,len,fd);
	    ep->doCalculation();
	    cout << "Going to exit" << endl;
	    //exit(1);
    	  }
      }
    else {
      cout << "Cookie is present" << endl;
      endpoint * ep = epdb[be64toh(isakmph->responder_cookie)];
      cout << ep << endl;
      cout << ep->iSPI << endl;
      ep->recv(data,len,fd);

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
	cout << "received length = " << recv_len << " " << ntohs(si_other.sin_port) << " " << hex << ntohl(si_other.sin_addr.s_addr)<< dec << endl;
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
      // try to receive data
      if((recv_len = recvfrom(s,buf,BUFLEN,0,(sockaddr *) &si_other,&s_len)) == -1)
	{
	  cout << "recv failed" << endl;
	  exit(1);
	}
      buf[recv_len] = '\0';
      cout << "buf = " << buf << " len = " << recv_len <<endl;

    }
}
