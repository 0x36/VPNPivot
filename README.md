VPN Pivot!
===================
You can find here a tutorial about how to use VPNPivot with examples : http://blog.0x36.org/?p=57

Sometime we do external penetration testing and when we compromise the remote target we would love to explore the internal network behind and getting such compromise like owning Active directory, accessing shared files ... etc.
There are many techniques like port forwarding, socks4 ..., but each one has its pros and cons . this is the reason why VPN pivoting techniques is out , it solves all the problems encountered by using both of the techniques mentioned above.
it lets you interact with internal networks that are prevented by firewalls,NATs .. etc

This an implementation of **VPN pivoting** technique in Linux using pure low-level sockets within tap device.
It creates a fully encrypted tunnel using a shared key between the target machine and the attacker.
 
----------


How it works
-------------
VPN Pivot sends and receive a fully encrypter TCP/IP stack over TCP socket,then the peers forward it into the desired device.
The attacker explores the internal network as he belongs to it within a local IP address taken from the dhcp server or statically configured . the used IP will never be reachable which makes him harder to track.

>**VPN Server: **
The VPNPivot server must be run in the the attacker machine, it creates a a virtual device (tap)  with the possibility to change MAC (that seems fine for spoofing and Mac switching) , IP address , MTU and also the owner of the interface.
The TAP devices interacts with the targets machine, it sends/receives raw ethernet frame.
Once the attacker get a successfully tunnel connection, the tap device can intercats with the DHCP server of the internal hacked network, receives/send broadcast packets, and also IP addresses reuse.

>**VPN Client: **
The VPN Pivot client must be run in the target machine, it creates two socket files , the first as client for the tunnel and the second for interacting with the device directly.
it works like we are creating a undetectable tap device which makes it harder to detect.
 
---------

Usage
-------------
**Compilation :**
```shell
~/projects/VPNPivot$ make
  [CC] vpnp_server.o
  [CC] crypto.o
  [BIN] vpnp_server
  [CC] vpnp_client.o
  [BIN] vpnp_client
  ---------
**vpnp_server :**
> ./vpnp_server -i pwn0 -I 10.10.10.145/24 -m 1500 -H 0c:0a:DE:AD:BE:EF -K "I0wnY0u*!" -v**
[+] Setup a non-persistent tap : pwn0
[+] Listening on port : 12345
```
So it creates an a tap device named pwn0 as shown bellow:
```shell
~$ ifconfig pwn0
pwn0      Link encap:Ethernet  HWaddr 0c:0a:de:ad:be:ef  
          inet adr:192.168.200.70  Bcast:192.168.200.255  Masque:255.255.255.0
          adr inet6: fe80::887e:86ff:fe8a:3599/64 Scope:Lien
          UP BROADCAST RUNNING  MTU:1500  Metric:1
          Packets reçus:0 erreurs:0 :0 overruns:0 frame:0
          TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 lg file transmission:500 
          Octets reçus:0 (0.0 B) Octets transmis:0 (0.0 B)
```
finally, it waits for the client to be connected 
```shell
**vpnp_client :**
> Usage : 
./vpnp_client 10.254.30.53 12345 10.10.10.1 "I0wnY0u*!"
```
That's it :-) , enjoy your pwning 

TODO
-------------
The main focus for the moment is to port the client to windows, The client is mainly designed to be portable and doesn't require any dependencies, 
Since windows doesn't support data link layer manipulation with WinSock ,thus we should hook some kernel function (NDIS hooks?).

