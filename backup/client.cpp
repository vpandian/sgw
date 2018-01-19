#include<stdio.h> //printf
#include<string.h> //memset
#include<stdlib.h> //exit(0);
#include<arpa/inet.h>
#include<sys/socket.h>
#include<iostream>
#define SERVER "192.168.1.11"
#define BUFLEN 512  //Max length of buffer
#define PORT 8888   //The port on which to send data
 
using namespace std;
 
int main(void)
{
    struct sockaddr_in si_other;
    int s, i, slen=sizeof(si_other), recv_len;
    char buf[BUFLEN];
    char message[BUFLEN];
 
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
 
    while(1)
    {
        printf("Enter message : ");
        cin >> message;
         
        //send the message
        if (sendto(s, message, strlen(message) , 0 , (struct sockaddr *) &si_other, slen)==-1)
        {
	  cout << "send problem" << endl;
        }
         
        //receive a reply and print it
        //clear the buffer by filling null, it might have previously received data
    }
 
    return 0;
}
