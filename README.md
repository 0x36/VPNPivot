## VPN Pivot:

Sometime we do external penetration testing and when we compromise the remote target we would like to explore the internal network behind and getting such compromise like owning Active directory, accessing shared files, conducting MITM attacks ... etc.
There are many techniques around like port forwarding, socks4 ..., but each one has its pros and cons. 
this is the reason why VPN pivoting techniques is out, it solves all the problems encountered by using both of the techniques mentioned above. It lets you interact with internal networks that are prevented by firewalls, NATs... etc.


This is an implementation of **VPN pivoting** technique in Linux using pure low-level sockets within tap device.
It creates a fully encrypted tunnel using a SSL/TLS between the target machine and the attacker.

### How it works:
VPN Pivot sends and receive a fully encrypted TCP/IP stack over TCP stream socket, then the peers forward it into the desired device/host.
The attacker explores the internal network as he belongs to it within a local IP address taken from the dhcp server or statically configured.

### Installation :
#### Arch Linux
```
yaourt -S vpnpivot-git
```
#### Linux
The installation is pretty straightforward, just type the following commands:
```bash
root@pwnies:~# git clone https://github.com/0x36/VPNPivot.git
root@pwnies:~# cd VPNPivot
root@pwnies:~/VPNPivot# ./autogen.sh
root@pwnies:~/VPNPivot# ./configure
root@pwnies:~/VPNPivot# make && make install
```

### VPN Server (pivots):

The VPNPivot server must be run in the attacker machine, it creates a virtual device (tap) with the possibility to change MAC (that seems fine for spoofing and Mac switching), IP address, MTU and also the owner of the interface.
The TAP devices interacts with the targets machine, it sends/receives raw Ethernet frame.
Once the attacker get a successfully tunnel connection, the tap device can interacts with the DHCP server of the internal hacked network, receives/send broadcast packets, and also IP addresses reuse.

Working with **pivots** is very easy, you only need to know what does each option:
```bash
root@pwnies:~/VPNPivot# ./src/pivots -h
 __      _______  _   _ _____ _            _ 
 \ \    / /  __ \| \ | |  __ (_)          | |  
  \ \  / /| |__) |  \| | |__) |__   _____ | |_ 
   \ \/ / |  ___/| . ` |  ___/ \ \ / / _ \| __|
    \  /  | |    | |\  | |   | |\ V / (_) | |_ 
     \/   |_|    |_| \_|_|   |_| \_/ \___/ \__|
                 
VPNPivot server v1.0 by Simo36
  -i  --iface   <device>		Create a non persistent tap device 
  -I  --ifconf  <ip/mask>		Inteface configuration (IP/MASK)
  -p  --port    <port>			Server port listener (default: 12345)
  -m  --mtu     <size>			Virtual devince MTU size (default: 1550)
  -u  --user    <user>			User device owner (OPTIONAL)
  -H  --hw      <MAC>			Set MAC address for the iface
  -C  --cert    <server_cert>   Filename of PEM certificate
  -P  --pkey    <private_key>   Filename of PEM private key
  -v  --verbose					Verbose mode
  -d							Deamonize
root@pwnies:~/VPNPivot# 

```
All the options above are optional, but they worth to be explained even their descriptions are self-explanatory:

* **--iface**  	: the virtual interface name being created (default: is chosen by the kernel).
* **--ifconf** 	: you can put a static IP address within a mask, otherwise, dhclient can be used to get network configuration from the internal hacked network.
* **--port**   	: you can choose any port number (default is :12345)
* **--mtu**    	: it's recommended to not change this and let the pivots handles it!
* **--user**   	: The owner of the device (useless for the moment)
* **--hw** 		: You can put any HW address in format like : AA:BB:CC:DD:EE:FF
* **--cert**	: the certificate file to use for SSL/TLS encryption
* **--pkey**	: the private key file to use for SSL/TLS encryption
* **--verbose**	: make more verbosity
* **-d**		: daemonize pivots


### VPN Client (pivotc):
The VPN Pivot client must be run in the target machine, it creates two socket files, the first as a client for the tunnel and the second for interacting with the device network directly.
It works like we are creating an undetectable tap device which makes it harder to detect.

Working with **pivotc** is easier than the server, you only need to be not confused when you are attempting to make it connect into **pivots** :
```bash
root@pwnies:~/VPNPivot# ./src/pivotc   
Usage : 
./src/pivotc <server IP> <server port> <locale IP> [MTU]
root@pwnies:~/VPNPivot#
```
The options are :
* **server IP** : the IP address of the server (pivots)
* **server port** : the port which the server is listening on
* **locale IP** : the IP address of the network interface connected to the unreachable network.
* **MTU**		: the MUT is optional unless you're changing it in **pivots**

### Case study:
There is nothing better than live demo, this is why I made a video, explaining the basic usage of VPNPivot, and the video is [on youtube](https://www.youtube.com/watch?v=VauxUK3OZnQ).

That's it! enjoy you pwning :-)
Cheers
