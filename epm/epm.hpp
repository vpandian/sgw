#include "udp_socket.hpp"
#include <sys/epoll.h>
#include "commondefs.hpp"
const int APP_COUNT = 16;
class endpoint_manager : public udp_socket
{
public:
  int lfd,efd;
  int app_db[APP_COUNT] = {0};
  epoll_event ev;
  struct epoll_event event;
  struct epoll_event *events;
  VatMemPool * mp_obj;
  size_t block_size;

  endpoint_manager(uint16_t port) : udp_socket(port)
  {
    std::cout << "end point constructor" << std::endl;
  uint8_t myStr[] = "1024";
  block_size = 1024;
  uint32_t init_count = 3;
  uint32_t exp_count = 1;
  mp_obj = new VatMemPool(myStr, block_size, init_count, exp_count);

  if((lfd = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP)) == -1)
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
    si_me.sin_port = htons(MUX_LISTEN_PORT);
    si_me.sin_addr.s_addr = htonl(INADDR_ANY);
    
    // bind the socket to port
    
    if(bind(lfd,(sockaddr *)&si_me, sizeof(si_me)) == -1)
      {
	perror("cannot bind");
	exit(1);
      }

    if(listen(lfd, 10) == -1)
      {
	perror("Cannot listen!");
	exit(1);
      }
  
    events = (epoll_event *)calloc(MAXEVENTS,sizeof(epoll_event));
    if((efd = epoll_create(MAXEVENTS)) == -1)
      {
	perror("epoll create error");
	exit(1);
      }
    ev.events = EPOLLIN | EPOLLET;
    ev.data.fd = lfd;
  
    if (epoll_ctl(efd,EPOLL_CTL_ADD,lfd,&ev)<0)
      {
	perror("epoll create error");
	exit(1);
      }
  }    
  void recv(sockaddr_in * peer, vat_mempool_t * ptr, int len, udp_socket & obj);
  void epoll_accept();
};
