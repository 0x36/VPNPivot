/*
 * 	Tool: Explore The Network VPN Pivoting server v0.2
 * 	Author: Simo Ghannam
 * 	Contact: <simo.ghannam@gmail.com>
 * 	Coded: 24 June 2015
 *
 * 	Description:
 * 	VPN pivoting tool for penetration testing
 *
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 *
 *      This program is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *      GNU General Public License for more details.
 *
 *      You should have received a copy of the GNU General Public License
 *      along with this program; if not, write to the Free Software
 *      Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 *      02111-1307  USA
 *
*/



#include "etn.h"

void banner(const char *);
static int dev_init(struct netdev*);
static int dev_xmit(struct netdev*,struct socket*);
static int dev_exit(struct netdev*);
static void parse_conf(char *,struct netdev*);
static struct socket *sock_accept(struct netdev *);

/* verbose mode */
int verbose = 0,daemonize =0;
int has_ifconf = 0;
u_char *hwaddr;
unsigned char *shr_key = NULL;

struct netdev_ops nd_ops = {
	.init = dev_init,
	.xmit = dev_xmit,
	.exit = dev_exit,
};

struct option long_opt[]= {
	{"help",0,NULL,'h'},
	{"iface",1,NULL,'i'},
	{"ifconf",1,NULL,'I'},
	{"port",1,NULL,'p'},
	{"user",1,NULL,'u'},
	{"verbose",0,NULL,'v'},
	{"mtu",1,NULL,'m'},
	{"hw",1,NULL,'H'},
	{"skey",1,NULL,'K'},
	{"daemon",0,NULL,'d'},
	{NULL,0,NULL,0},

};


int main(int argc,char **argv)
{
	int opt,long_opt_index = 0,ret;
	struct netdev *vdev,dev;
	struct socket sk;
	u_char *ifconf;
	struct linger so_linger;
	u_int mtu=0;

	memset(&dev,0,sizeof(struct netdev));
	memset(&sk,0,sizeof(struct socket));
	ifconf = NULL;
	vdev = &dev;
	vdev->nd_ops = &nd_ops;
	vdev->sk = &sk;

	while( (opt =getopt_long(argc,argv,"hi:I:p:u:vm:H:K:d",long_opt,&long_opt_index)) != -1 ) {
		switch(opt) {
		case 'h':
			banner(argv[0]);
			break;
		case 'i':
			memcpy(&dev.nd_name,optarg,IFNAMSIZ-1);
			break;
		case 'I':
			ifconf = (u_char*)strdup(optarg);
			has_ifconf |=1;
			break;
		case 'p':
			sk.sk_port = atoi(optarg);
			break;
		case 'u':
			dev.nd_owner = (u_int8_t*)strdup(optarg);
			break;
		case 'v':
			verbose |= 1;
			break;
		case 'm':
			mtu = atoi(optarg);
			break;
		case 'K':
			shr_key = (unsigned char*)strdup(optarg);
			break;
		case 'H':
			hwaddr = (u_char *)strdup(optarg);
			break;
		case 'd':
			daemonize |=1;
			break;
		default:
			banner(argv[0]);
			break;
		}
	}
	
	/* device name is not required , 
	   the kernel will give us a random name  */
	dev.nd_flags = IFF_TAP | IFF_NO_PI;
	if(daemonize)
		if(daemon(0,0) == -1) {
			perrx("main():daemon()");
			return -1;
		}

	if(!has_ifconf ) {
		fprintf(stderr,"[!] Device configuration is not set \n");
	} else 
		parse_conf((char*)ifconf,&dev);

	if (!sk.sk_port) 
		sk.sk_port = DEFAULT_PORT;
	
	if(!mtu || mtu < 0 || mtu > 4096)
		vdev->nd_mtu = MTU;
	else
		vdev->nd_mtu = mtu;
	
	if(shr_key == NULL) {
		printf("[-] Shared key is not set\n");
		return -1;
	}
	sk.sk_fd = socket(AF_INET,SOCK_STREAM,0);
	if(sk.sk_fd < 0) {
		perror("main():socket()");
		return -1;
	}

	/* set linger socket option  */
	so_linger.l_onoff = 1;
	so_linger.l_linger = 0;
	
	ret = setsockopt(sk.sk_fd,SOL_SOCKET,SO_LINGER,&so_linger,sizeof(struct linger));
	if(ret == -1) {
		perror("main:setsockopt(SO_LINGER)");
		close(sk.sk_fd);
		return ret;
	}

	/* let's create a virtual device interface */
	if(vdev->nd_ops->init(&dev))
		return -1;
	
	int yes = 1;
	struct socket *sk_cli;
	
	sk.sk_serv.sin_family = AF_INET;
	sk.sk_serv.sin_port = htons(sk.sk_port);
	sk.sk_serv.sin_addr.s_addr = htonl(INADDR_ANY);
	
	/* enable socket address re-use */
	ret = setsockopt(sk.sk_fd,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(yes));
	if(ret == -1) {
		perror("main:setsockopt(SO_REUSEADDR)");
		close(sk.sk_fd);
		return ret;
	}
	ret = bind(sk.sk_fd,(struct sockaddr*)&sk.sk_serv,sizeof(struct sockaddr_in));
	if(ret == -1) {
		perror("main:bind()");
		close(sk.sk_fd);
		return ret;
	}
	ret = listen(sk.sk_fd,4);
	if(ret == -1) {
		perror("main:listen()");
		return -1;
	}
	if(verbose) 
		printf("[+] Listening on port : %d\n",sk.sk_port);
	
	for(;;) {
		sk_cli =sock_accept(&dev);
		if(!sk_cli)  
			return -1;
		vdev->nd_ops->xmit(vdev,sk_cli);
	}
		
	vdev->nd_ops->exit(vdev);
	return 0;
}

static int dev_init(struct netdev* dev)
{
	struct ifreq ifr;
	struct sockaddr_in *saddr;
	
	memset(&ifr,0,sizeof(struct ifreq));
	
	/* open tap device  */
	dev->nd_fd = open(TUNFILE,O_RDWR);
	if (dev->nd_fd == -1) {
		perror("dev_init():open()");
		return -1;
	}
	if(dev->nd_name)
		memcpy(ifr.ifr_name,dev->nd_name,IFNAMSIZ);
	
	ifr.ifr_flags = dev->nd_flags;
	if(ioctl(dev->nd_fd,TUNSETIFF,(void*)&ifr) < 0) {
		perror("dev_init():ioctl(TUNSETIFF)");
		return -1;
	}

	memcpy(dev->nd_name,ifr.ifr_name,IFNAMSIZ);
	if(verbose)
		printf("[+] Setup a non-persistent tap : %s\n",
		       dev->nd_name);
	
	/* if the device configuration is not set
	   we should wait for dhcp configuration from
	   the internal pwned network 
	 */
	if(has_ifconf) {
		/* set  network ip address  */
		saddr = (struct sockaddr_in*)&ifr.ifr_addr;
		saddr->sin_family = AF_INET;
		saddr->sin_addr.s_addr = dev->nd_ipaddr;
		if(ioctl(dev->sk->sk_fd,SIOCSIFADDR,(void*)&ifr) < 0) {
			perror("dev_init:ioctl(SIOCSIFADDR)");
			return -1;
		}
		
		/* set netmask  */
		saddr = (struct sockaddr_in*)&ifr.ifr_netmask;
		saddr->sin_family = AF_INET;
		saddr->sin_addr.s_addr = htonl(dev->nd_netmask);
		if(ioctl(dev->sk->sk_fd,SIOCSIFNETMASK,(void*)&ifr) < 0) {
			perror("dev_init:ioctl(SIOCSIFNETMASK)");
			return -1;
		}
	}
	
	/* fire up the device  */
	ifr.ifr_flags |= IFF_UP |IFF_RUNNING;
	if(ioctl(dev->sk->sk_fd,SIOCSIFFLAGS,(void*)&ifr) < 0) {
		perror("dev_init:ioctl(SIOCSIFFLAGS)");
		return -1;
	}
	if(hwaddr != NULL) {
		if(sscanf((const char*)hwaddr,"%02x:%02x:%02x:%02x:%02x:%02x",
			  (unsigned int*)&dev->nd_hwaddr[0],
			  (unsigned int*)&dev->nd_hwaddr[1],
			  (unsigned int*)&dev->nd_hwaddr[2],
			  (unsigned int*)&dev->nd_hwaddr[3],
			  (unsigned int*)&dev->nd_hwaddr[4],
			  (unsigned int*)&dev->nd_hwaddr[5]) == 6) {
			
			memset((char*)&ifr.ifr_hwaddr,0,sizeof(struct sockaddr));
			memcpy((char*)&ifr.ifr_hwaddr.sa_data,
			       dev->nd_hwaddr,
			       6);
			ifr.ifr_hwaddr.sa_family = 1; /* Hardware Type (ETHER) */
			if(ioctl(dev->nd_fd,SIOCSIFHWADDR,&ifr) < 0) 
				perrx("dev_init:ioctl(SIOCSIFHWADDR)");
			
		} else 
			printf("dev_init:Invalid Hardware address!\n");
	}	
	/* set MTU */
	ifr.ifr_mtu = dev->nd_mtu;
	if(ioctl(dev->sk->sk_fd,SIOCSIFMTU,(void*)&ifr) < 0) {
		perror("dev_init:ioctl(SIOCSIFFLAGS)");
		return -1;
	}
	
	/* set ownership */
	if(dev->nd_owner) {
		struct passwd *pwd = getpwnam((const char*)dev->nd_owner);
		if(!pwd) {
			perror("dev_init():getpwname()");
			return -1;
		}
		if(ioctl(dev->nd_fd,TUNSETOWNER,pwd->pw_uid) < 0) {
			perror("dev_init():ioctl(SETOWNERSHIP)");
			return -1;
		}
		if(ioctl(dev->nd_fd,TUNSETGROUP,pwd->pw_uid) < 0) {
			perror("dev_init():ioctl(SETOGROUP)");
			return -1;
		}

	}
	return 0;
}
static int dev_xmit(struct netdev* dev,struct socket *sk)
{
	fd_set in;
	int ret,maxfd;
	struct mbuf mb;
	struct rc4_context ctx;
	
	rc4_prepare_shared_key(&ctx,shr_key);
	memset(&mb,0,sizeof(struct mbuf));
	
	mb.mb_data = (u_int8_t*)malloc(dev->nd_mtu * sizeof(u_int8_t));
	if(!mb.mb_data) {
		perror("dev_xmit:malloc");
		return -1;
	}
	memset(mb.mb_data,0,sizeof(dev->nd_mtu*sizeof(u_int8_t)));
	printf("[+] Connected ... OK\n");
	
	FD_ZERO(&in);
	
	maxfd = (sk->sk_fd > dev->nd_fd)? sk->sk_fd:dev->nd_fd;
	for(;;) {
		FD_SET(dev->nd_fd,&in);
		FD_SET(sk->sk_fd,&in);

		ret = select(maxfd+1,&in,NULL,NULL,NULL);
		if(ret == -1 || errno == EINTR)
			continue;
		
		/* we got something from tun/tap inetface */
		if(FD_ISSET(dev->nd_fd,&in)) {
			mb.mb_len = read(dev->nd_fd,mb.mb_data,dev->nd_mtu);
			if(mb.mb_len == 0) 
				break;
			if(mb.mb_len < 0) {
				if(verbose) 
					perrx("[-] TAP read error");
				goto bad;
			}
			
			rc4_cipher(mb.mb_data,mb.mb_len,&ctx);
			if (verbose)
				printf("[+] Received %d bytes from %s \n",
				       (unsigned int)mb.mb_len,dev->nd_name);
			mb.mb_len = write(sk->sk_fd,mb.mb_data,mb.mb_len);
			if(mb.mb_len <= 0) {
				if(verbose)
					perrx("[-] TAP write error");
				goto bad;
			}	
		}
		
		if(FD_ISSET(sk->sk_fd,&in)) {
			mb.mb_len = read(sk->sk_fd,mb.mb_data,dev->nd_mtu);
			if(mb.mb_len == 0) 
				break;
			if(mb.mb_len < 0) {
				if(verbose) 
					perrx("[-] Socket read error\n");
				goto bad;

			}
				
			if (verbose)
				printf("[+] Received %d bytes from socket\n",(unsigned int)mb.mb_len);
			rc4_cipher(mb.mb_data,mb.mb_len,&ctx);
			mb.mb_len = write(dev->nd_fd,mb.mb_data,mb.mb_len);
			if(mb.mb_len <= 0) {
				if(verbose)
					perrx("[-] Socket write error");
				goto bad;
			}	

		}
		
	}
	return 0;

bad:
	close(sk->sk_fd);
	close(dev->nd_fd);
	if(mb.mb_data)
		free(mb.mb_data);
	return -1;
	
}
static int dev_exit(struct netdev* dev)
{
	if(ioctl(dev->nd_fd,TUNSETPERSIST,0) < 0) {
		perror("ioctl(TUNSETPERSIST) false");
		close(dev->nd_fd);
		return -1;
	}
	return 0;
	
}

/* ifconf syntaxe : 1.1.1.1/24 */
static void parse_conf(char *ifconf , struct netdev* dev)
{
	char  *nmask = strchr(ifconf,'/');
	u_int8_t ipaddr[16]={0};
	in_addr_t netmask = 0xffffffff;
	
	if(!nmask) {
		fprintf(stderr,"[-] ifconf syntax error \n");
		exit(0);
	}
	memcpy(ipaddr,ifconf,(u_int32_t)(nmask-ifconf));
	nmask++;
	
	dev->nd_ipaddr = inet_addr((const char*)ipaddr);
	if(dev->nd_ipaddr == INADDR_NONE) {
		fprintf(stderr,"[-] Invalid ip addr \n");
		exit(1);
	}
		
	netmask = (netmask << (32-atoi(nmask)));
	dev->nd_netmask = netmask;
#if 0
	
	printf("netmask : %08x\n",netmask);
	printf("ipaddr : %s\n",ipaddr);
#endif
}

static struct socket *sock_accept(struct netdev *dev)
{
	fd_set in;
	int ret;
	int clifd;
	socklen_t sklen;
	struct socket *sk = dev->sk;
	struct socket *sk_ret;
	
	FD_ZERO(&in);
	FD_SET(sk->sk_fd,&in);
do_select:
	ret = select(sk->sk_fd+1,&in,NULL,NULL,NULL);
	if (ret == -1) {
		if (errno == EINTR) 
			goto do_select;
		else {
			perror("sock_accept:select");
			close(sk->sk_fd);
			return NULL;
		}
	}
	if(FD_ISSET(sk->sk_fd,&in)) {
		clifd = accept(sk->sk_fd,(struct sockaddr*)&sk->sk_cli,&sklen);
		if(clifd == -1) {
			perror("sock_accept:accept()");
			exit(1);
		}
		if(verbose) 
			fprintf(stdout,"connection from (%s:%d).\n",
				inet_ntoa(sk->sk_cli.sin_addr),ntohs(sk->sk_cli.sin_port));
	
	
		sk_ret = (struct socket*)malloc(sizeof(struct socket));
		if(!sk_ret)
			return NULL;
		memset(sk_ret,0,sizeof(struct socket));
		sk_ret->sk_fd = clifd;
		sk_ret->sk_port = ntohs(sk->sk_cli.sin_port);
		sk_ret->sk_ip = htonl(sk->sk_cli.sin_addr.s_addr);
		memcpy(&sk_ret->sk_cli,&sk->sk_cli,sizeof(struct sockaddr_in));
		/* hold the socket server infomations */
		memcpy(&sk_ret->sk_serv,&sk->sk_serv,sizeof(struct sockaddr_in));
		return sk_ret;
		
	}
	/* the function should never reach this place */
	return NULL;
}

void banner(const char *argv)
{
	//printfd(1,"+-----------------------------------------+\n");
	printfd(1, "ETN VPN Pivot server v0.2 by Simo36\n");
	printfd(1,
		"  -i  --iface   <device>    \tCreate a non persistent tap device \n"
		"  -I  --ifconf  <ip/mask>\tInteface configuration (IP/MASK)\n"
		"  -p  --port    <port>   \tServer port listener (default: 12345)\n"
		"  -m  --mtu     <size>   \tVirtual devince MTU size (default: 1550)\n"
		"  -u  --user    <user>   \tUser device owner (OPTIONAL)\n"
		"  -H  --hw      <MAC>    \tSet MAC address for the iface\n"
		"  -K  --skey    <key>    \tExchange share key encryption\n"
		"  -v  --verbose            \tVerbose mode\n"
		"  -d                       \tDeamonize\n"
		"\n");

	exit(0);
}
