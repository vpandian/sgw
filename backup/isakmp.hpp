#ifndef __ISAKMP_HPP__
#define __ISAKMP_HPP__

#include<stdint.h>

class ipsecEndpoint
{
public:
  uint32_t ip;
  uint8_t spi[8];
  uint8_t nonce[32];
  uint32_t nonce_len;
  uint8_t public_key[1024];
  ipsecEndpoint()
  {
    ip = 0;
    memset(spi,0,sizeof(spi));
    memset(nonce,0,sizeof(nonce));
    nonce_len = 0;
    memset(public_key,0,sizeof(public_key));
  }
};

class ipsecSession
{
public:
    ipsecEndpoint initiator;
    ipsecEndpoint responder;
};

#endif
