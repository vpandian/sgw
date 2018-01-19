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
parser p;


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
  just_send((uint8_t *)buf, l, fd,ip_v4);
  
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
	    just_send((uint8_t *)isakmph, l, fd, ip_v4);

	  }
	else
	  {
	    cout << "cookie is present" << endl;
	    // assign a responder SPI
	    //endpoint * ep = new endpoint(be64toh(isakmph->initiator_cookie), alloc_rSPI());
	    endpoint * ep = new endpoint(isakmph->initiator_cookie, be64toh(alloc_rSPI()), ip_v4);
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
