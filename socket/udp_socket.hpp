#ifndef __UDP_SOCKET__
#define __UDP_SOCKET__

class udp_socket
{
protected:
  uint16_t port;
public:
  int ulfd;
  udp_socket(uint16_t _port);
  int udp_listener(sockaddr_in * si_other, uint8_t * buf, int len);
  int udp_sender(sockaddr_in * peer, uint8_t * buf, int len);

};

#endif
