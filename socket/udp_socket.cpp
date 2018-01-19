#include <iostream>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "../mempool/mempool.hpp"
#include "../epm/epm.hpp"
#include "udp_socket.hpp"

using namespace std;

class socket
{
  
public:
  socket()
  {
  }

  ~socket()
  {
  }

};

udp_socket::udp_socket(uint16_t _port)
  {
    cout << "calling constructor port "<< _port<< endl;
    port = _port;

    // create a UDP socket
    if((ulfd = socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP)) == -1)
      {
	perror("cannot create server listening socket");
	exit(1);
      }
    int yes;
    if(setsockopt(ulfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
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
    
    if(bind(ulfd,(sockaddr *)&si_me, sizeof(si_me)) == -1)
      {
	perror("cannot bind");
	exit(1);
      }

  }

int udp_socket::udp_listener(sockaddr_in * si_other, uint8_t * buf, int len)
{ 
    // Accept all the data
  int recv_len = 0;
  socklen_t s_len = sizeof(sockaddr_in);

  if((recv_len = recvfrom(ulfd,buf,len,0,(sockaddr *) si_other,&s_len)) == -1)
    {
      perror("Recv failed");
      return -1;
    }
  return recv_len;
}
int udp_socket::udp_sender(sockaddr_in * peer, uint8_t * buf, int len)
{ 
    // Accept all the data
  int recv_len = 0;
  socklen_t s_len = sizeof(sockaddr_in);


  //send the message
  if (sendto(ulfd,buf, len , 0 , (struct sockaddr *) peer, s_len)==-1)
    {
      cout << "send problem" << endl;
      return -1;
    }
  //cout << "sent successfully" << endl;
  return len;
}




int main()
{
  //udp_socket obj(8888);

  uint8_t myStr[] = "1024";
  size_t block_size = 1024;
  uint32_t init_count = 3;
  uint32_t exp_count = 1;
  VatMemPool mp_obj(myStr, block_size, init_count, exp_count);
  endpoint_manager ep_obj(8888);

  while(true)
  {
    fd_set rfd;
    FD_ZERO(&rfd);
    FD_SET(ep_obj.ulfd,&rfd);
    FD_SET(ep_obj.efd,&rfd);
    int ret = select(ep_obj.efd+1,&rfd,NULL,NULL,NULL);
    if(ret == -1)
      {
	perror("select error");
	exit(-1);
      }
    if(FD_ISSET(ep_obj.ulfd,&rfd))
      {
	sockaddr_in si_other;
	vat_mempool_t * ptr = mp_obj.vat_mempool_alloc();
	if(! ptr)
	  {
	    cout << "No more buf available from mem pool.. exiting" << endl;
	    exit(-1);
	  }
	int len = ep_obj.udp_listener(&si_other, ptr->location, block_size);
	ep_obj.recv(&si_other,ptr,len,ep_obj);
	mp_obj.vat_mempool_free(ptr);
      }
    else if(FD_ISSET(ep_obj.efd,&rfd))
      {
	cout << "received application connection,data" << endl;
	ep_obj.epoll_accept();
      }
    //epm.recv(ntohs(si_other.sin_port),ntohl(si_other.sin_addr.s_addr),buf,recv_len, lfd);
  }
}
