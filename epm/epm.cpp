#include<iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include "mempool.hpp"
#include "commondefs.hpp"

#include "epm.hpp"
#include "udp_socket.hpp"
using namespace std;


sockaddr_in app_to_client[16] = {0};
void endpoint_manager::epoll_accept()
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
	  struct sockaddr_in in_addr;
	  socklen_t in_len;
	  cout << "Incomming connection" << endl;
	  in_len = sizeof(sockaddr_in);
	  int infd = accept(lfd, (struct sockaddr *)&in_addr, &in_len);
	  if (infd == -1)
	    {
	      perror ("accept:");
	      exit(-1);
	    }

	  int flags = fcntl (infd, F_GETFL, 0);
	  if (flags == -1)
	    {
	      perror ("fcntl1");
	      exit(-1);
	    }
		
	  flags |= O_NONBLOCK;
	  int s = fcntl (infd, F_SETFL, flags);
	  if (s == -1)
	    {
	      perror ("fcntl2");
	      exit(-1);
	    }
	  
		
	  event.data.fd = infd;
	  event.events = EPOLLIN | EPOLLET;
	  s = epoll_ctl (efd, EPOLL_CTL_ADD, infd, &event);
	  if (s == -1)
	    {
	      perror ("epoll_ctl");
	      abort ();
	    }

	  bool is_set = false;
	  // add the app details in the APP DB.
	  for(int i = 0; i<APP_COUNT;i++)
	    {
	      if(app_db[i] == 0)
		{
		  app_db[i] = infd;
		  is_set = true;
		  cout << "Added app fd " << infd
		       << " to the app_db index "<< i << endl;
		  break;
		}
	    }
	  if(!is_set)
	    {
	      cout << "App details not updated in the app_db" << endl;
	      exit(-1);
	    }
	}
      else
	{
	  // Accept all the data
	  while(true)
	    {
	      sockaddr_in si_other;
	      int recv_len = 0;
	      socklen_t s_len = sizeof(sockaddr_in);
	      vat_mempool_t * ptr = mp_obj->vat_mempool_alloc();
	      if(! ptr)
		{
		  cout << "No more buf available from mem pool.. exiting" << endl;
		  exit(-1);
		}

      
	      if((recv_len = recvfrom(events[i].data.fd,ptr->location,block_size,0,(sockaddr *) &si_other,&s_len)) == -1)
		{
		  if ((errno == EAGAIN) || (errno == EWOULDBLOCK))
		    {
		      printf("non-blocking operation returned EAGAIN or EWOULDBLOCK\n");
		      break;
		    }
		  else
		    {
		      perror("Recv failed");
		      exit(1);
		    }
		}
	      if(recv_len == 0)
		{
		  cout << "application disconneting" << endl;
		  epoll_ctl(efd, EPOLL_CTL_DEL, events[i].data.fd, &ev);
		  close(events[i].data.fd);
		  for(int i = 0; i<APP_COUNT;i++)
		    {
		      if(app_db[i] == events[i].data.fd)
			 {
	                   app_db[i] = 0;
			   cout << "removed app fd " << events[i].data.fd
				<< " from the app_db index "<< i << endl;
			   break;
	                 }
	            }

	  
		  break;
		}
	      cout << "si_other port = " 
		   <<  ntohs(si_other.sin_port)
		   << " IP = " << inet_ntoa(si_other.sin_addr) << endl;
	      
	      ptr->location[recv_len] = '\0';
	      cout << "buf = " << ptr->location << " len = " << recv_len <<endl;
	      
	      // send the data to the client..
	      cout << "dropping packets.." << endl;
	      udp_sender(&app_to_client[events[i].data.fd],ptr->location,recv_len);
	      #if 0
	      if (sendto(events[i].data.fd, ptr->location, recv_len , 0 , (struct sockaddr *) &si_other, sizeof(si_other))==-1)
		{
		  cout << "send problem" << endl;
		}
	      #endif
	    }
	}
      
    }

}

int client_db[65536] = {0};
void endpoint_manager::recv(sockaddr_in * peer, vat_mempool_t * ptr, int len,udp_socket & obj)
{
  cout << "received length = " << len << " "
       << ntohs(peer->sin_port) << " "
       << ntohl(peer->sin_addr.s_addr)<< endl;
  // send the packet to the applicayion..
  // mapping port to the app
  uint16_t port = ntohs(peer->sin_port);
  int app_fd = client_db[port];
  if(!app_fd)
    {
      // allocate app.. first non zero app
      for(int i = 0; i<APP_COUNT;i++)
	{
	  if(app_db[i] != 0)
	    {
	      app_fd = app_db[i];
	      client_db[port] = app_fd;
	      app_to_client[app_fd] = *peer;
	      break;
	    }
	}
    }
  if(app_fd)
    {
      // encode the packet.. add ip address and port to the message

      // send it to the app
      if (sendto(app_fd, ptr->location, len , 0 , NULL , 0)==-1)
	{
	  cout << "send problem" << endl;
	}
      else
	{
	  cout << "successfully sent to app " << app_fd << endl;
	}
      
    }
  else
    {
      cout << "Dropping message.. no app found" << endl;
    }

}

#if 0
endpoint_manager::endpoint_manager(uint16_t port) : udp_socket(port)
{

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
#endif  
