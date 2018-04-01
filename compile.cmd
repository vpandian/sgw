 sudo apt-get install libcrypto++-dev libcrypto++-doc libcrypto++-utils
 
g++ -o sgw sgw.cpp -std=c++11 hash.cpp -lcryptopp -I epm/ mempool/mempool.cpp -I mempool/ -I socket/ parse.cpp ep.cpp aes.cpp -g tun.cpp -D USE_EPOLL


 openvpn --mktun --dev tun0
 sudo ip link set tun0 up
 sudo ip addr add 20.0.0.1/24 dev tun0
 

anbu@VAT-Server-2:~/ipsec/sgw$ ifconfig
eno1      Link encap:Ethernet  HWaddr d4:ae:52:a4:59:40  
          inet addr:192.168.1.6  Bcast:192.168.1.255  Mask:255.255.255.0
          inet6 addr: fe80::d6ae:52ff:fea4:5940/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:4016953 errors:0 dropped:0 overruns:0 frame:0
          TX packets:5573271 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:1368924928 (1.3 GB)  TX bytes:5228754147 (5.2 GB)

eno2      Link encap:Ethernet  HWaddr d4:ae:52:a4:59:41  
          UP BROADCAST MULTICAST  MTU:1500  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:189797 errors:0 dropped:0 overruns:0 frame:0
          TX packets:189797 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1 
          RX bytes:67368556 (67.3 MB)  TX bytes:67368556 (67.3 MB)

tun0      Link encap:UNSPEC  HWaddr 00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00  
          inet addr:20.0.0.1  P-t-P:20.0.0.1  Mask:255.255.255.0
          UP POINTOPOINT NOARP MULTICAST  MTU:1500  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:6 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:100 
          RX bytes:0 (0.0 B)  TX bytes:504 (504.0 B)

virbr0    Link encap:Ethernet  HWaddr 00:00:00:00:00:00  
          inet addr:192.168.122.1  Bcast:192.168.122.255  Mask:255.255.255.0
          UP BROADCAST MULTICAST  MTU:1500  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)

anbu@VAT-Server-2:~/ipsec/sgw$ ip route 
default via 192.168.1.1 dev eno1 
10.0.0.1 via 192.168.1.13 dev eno1 
20.0.0.0/24 dev tun0  proto kernel  scope link  src 20.0.0.1 linkdown 
30.0.0.0/24 via 20.0.0.1 dev tun0 linkdown 
169.254.0.0/16 dev eno1  scope link  metric 1000 
192.168.1.0/24 dev eno1  proto kernel  scope link  src 192.168.1.6 
192.168.122.0/24 dev virbr0  proto kernel  scope link  src 192.168.122.1 linkdown

vijay@raspberrypi ~ $ ifconfig
eth0      Link encap:Ethernet  HWaddr b8:27:eb:06:22:06  
          inet addr:192.168.1.13  Bcast:192.168.1.255  Mask:255.255.255.0
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:642147 errors:0 dropped:0 overruns:0 frame:0
          TX packets:22909 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:35438617 (33.7 MiB)  TX bytes:1937062 (1.8 MiB)

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:15 errors:0 dropped:0 overruns:0 frame:0
          TX packets:15 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0 
          RX bytes:1664 (1.6 KiB)  TX bytes:1664 (1.6 KiB)

lo:1      Link encap:Local Loopback  
          inet addr:10.0.0.1  Mask:255.0.0.0
          UP LOOPBACK RUNNING  MTU:65536  Metric:1

lo:2      Link encap:Local Loopback  
          inet addr:30.0.0.1  Mask:255.0.0.0
          UP LOOPBACK RUNNING  MTU:65536  Metric:1

vijay@raspberrypi ~ $ ip route 
default via 192.168.1.1 dev eth0 
20.0.0.1 via 192.168.1.6 dev eth0 
192.168.1.0/24 dev eth0  proto kernel  scope link  src 192.168.1.13 



/etc/ipsec.secrets:
===================
# This file holds shared secrets or RSA private keys for authentication.

# RSA private key for this host, authenticating it to any other host
# which knows the public part.

# this file is managed with debconf and will contain the automatically created \
private key
#include /var/lib/strongswan/ipsec.secrets.inc

%any : PSK hello
192.168.1.13 : PSK "hellohellohellohello"
192.168.1.16 : PSK "hellohellohellohello"
10.0.0.1 : PSK "hellohellohellohello"

/etc/ipsec.conf:
================
# Sample VPN connections                                                     

#conn sample-self-signed                                                     
#      leftsubnet=10.1.0.0/16                                                
#      leftcert=selfCert.der                                                 
#      leftsendcert=never                                                    
#      right=192.168.0.2                                                     
#      rightsubnet=10.2.0.0/16                                               
#      rightcert=peerCert.der                                                
#      auto=start                                                            

#conn sample-with-ca-cert                                                    
#      leftsubnet=10.1.0.0/16                                                
#      leftcert=myCert.pem                                                   
#      right=192.168.0.2                                                     
#      rightsubnet=10.2.0.0/16                                               
#      rightid="C=CH, O=Linux strongSwan CN=peer name"                       
#      auto=start                                                            

config setup

conn %default
     ikelifetime=60m
     keylife=20m
     rekeymargin=3m
     keyexchange=ikev2
     authby=secret

conn home
#     left=192.168.1.13                                                      
#     leftsubnet=192.168.1.0/24                                              
     left=10.0.0.1
     leftsubnet=30.0.0.0/24
     rightsubnet=20.0.0.0/24
     leftfirewall=yes
     right=192.168.1.6
     auto=add
     ike=modp1024
#     rightauth=secret                                                       
#     ike=aes256-sha-modp1024!                                               
#     esp=aes256-sha1                                                        
#     ike=aes128-sha-modp1024!                                               
#     esp=aes128-sha1                                                        
#     keyexchange=ikev1                                                      

#include /var/lib/strongswan/ipsec.conf.inc


/etc/stongswan.conf:
===================
# strongswan.conf - strongSwan configuration file                            
#                                                                            
# Refer to the strongswan.conf(5) manpage for details                        
#                                                                            
# Configuration changes should be made in the included files                 

charon {
        load_modular = yes
        plugins {
                include strongswan.d/charon/*.conf
        }
        # Logging                                                            
        syslog {
               # prefix for each log message                                 
               identifier = charon-anbu
               # use default settings to log to the LOG_DAEMON facility      
               daemon {
                      default = 1
               }
               # detailed IKE log                                            
               auth {
                    default = 1
               }
        }
        filelog {
                /var/log/charon.log {
                    # add a timestamp prefix                                 
                    time_format = %b %e %T
                    # prepend connection name, simplifies grepping           
                    ike_name = yes
                    # overwrite existing files                               
                    append = no
                    # increase default loglevel for all daemon subsystems    
                    default = 4
                    # flush each line to disk                                
                    flush_line = yes
                }
                stderr {
                       # more detailed loglevel for a specific subsystem, ov\
erriding the                                                                 
                       # default loglevel.                                   
                       ike = 4
                       knl = 4
                }
        }
}

include strongswan.d/*.conf
