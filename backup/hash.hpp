#ifndef __HASH_HPP__
#define __HASH_HPP__

class sha1
{
public:
  uint32_t h0, h1, h2, h3, h4;
  sha1();
  void transform1(uint8_t * data);
};

class hmac:public sha1
{
public:
  void key(uint8_t * k, uint32_t len, uint8_t pad);
  void transform(uint8_t * data, uint32_t len);
  void final();
  void result(uint32_t * buf);
};

#endif
