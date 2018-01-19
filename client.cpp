#include<stdio.h> //printf
#include<string.h> //memset
#include<stdlib.h> //exit(0);
#include<arpa/inet.h>
#include<sys/socket.h>
#include<iostream>
#define SERVER "192.168.1.8"
#define BUFLEN 512  //Max length of buffer
#define PORT 8888   //The port on which to send data
#include <sys/time.h> 
using namespace std;
 
int main(int argc,char * argv[])
{
    struct sockaddr_in si_other;
    int s, i, slen=sizeof(si_other), recv_len;
    char buf[BUFLEN];
 
    if ( (s=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
    {
      cout << "socket creation problem" << endl;
    }
 
    memset((char *) &si_other, 0, sizeof(si_other));
    si_other.sin_family = AF_INET;
    si_other.sin_port = htons(PORT);
     
    if (inet_aton(SERVER , &si_other.sin_addr) == 0) 
    {
        fprintf(stderr, "inet_aton() failed\n");
        exit(1);
    }
 
    int count = atoi(argv[1]);
    int tot_messages = count;
    char * message = argv[2];
    struct timeval tvs,tve;
    int start = gettimeofday(&tvs,NULL);
    while(count)
      {
	count--;
        //send the message
        if (sendto(s, message, strlen(message) , 0 , (struct sockaddr *) &si_other, slen)==-1)
        {
	  cout << "send problem" << endl;
        }
	
         
        //receive a reply and print it
        //clear the buffer by filling null, it might have previously received data
	int recv_len = 0;
	socklen_t s_len = sizeof(sockaddr_in);

	if((recv_len = recvfrom(s,message,BUFLEN,0,(sockaddr *) &si_other,&s_len)) == -1)
	  {
	    perror("Recv failed");
	    return -1;
	  }
	//cout << " received = " << message << endl;

    }
 
    int end = gettimeofday(&tve,NULL);
    suseconds_t tot_time = ((tve.tv_sec * 1000000) + tve.tv_usec) -
      ((tvs.tv_sec * 1000000) + tvs.tv_usec);
    cout << "diff = " << tve.tv_sec - tvs.tv_sec << endl;
    cout << "tot time = " << tot_time<< endl;
    cout << "rate = "<< (((uint64_t )tot_messages) * 1000000)/tot_time << endl;
    return 0;
}


