/*
 * 	Tool: VPNPivot client
 * 	Author: Simo Ghannam
 * 	Contact: <simo.ghannam@gmail.com>
 * 	Coded: 2015
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

#define IP_MAXPACKET	65535
#define IP_MAXRECV	1500

void banner(const char*);
/* open a devince in promiscious mode  */
int etn_setup_promisc(struct netdev*);
struct ifreq * lookup_dev(struct ifreq *,int *,struct netdev *);
static int etn_cli_recv(struct netdev *,struct socket *);
static int etn_cli_exit(struct netdev *);
void *mbuf_sock_hanler(void *);

unsigned char *shr_key=NULL;
struct netdev_ops nd_ops = {
	.init = NULL,		/* no need to create a virtual device */
	.xmit = etn_cli_recv,
	.exit = etn_cli_exit,
};

int main(int argc,char **argv)
{
	struct etnc_struct *etnc;
	struct netdev *nd;
	int ret;
	
	if(argc < 5)
		banner(argv[0]);
	if(argc == 5)
		shr_key = (unsigned char*)strdup(argv[4]);

	nd = xmalloc(sizeof(struct netdev*));
	etnc = xmalloc(sizeof(struct etnc_struct*));
	
	nd->nd_ipaddr = inet_addr(argv[3]);
	nd->nd_ops = &nd_ops;
	
	nd->sk = etn_sock_connect(argv[1],atoi(argv[2]));
	if(nd->sk == NULL) {
		printfd(2," Couldn't create the socket structure\n");
		ret = -1;
		goto bad;
	}
	
	if(etn_setup_promisc(nd) < 0) {
		ret = -1;
		goto bad;
	}

	return 0;

bad:
	//if(nd) free(nd);
	if(etnc) free(etnc);
	etn_sock_close(nd->sk);
	nd->nd_ops->exit(nd);
	return ret;
}

struct socket * etn_sock_connect(char *server,unsigned short port)
{
	int fd,ret;
	struct hostent *h;
	char **pptr;
	char ip[15]={0};
	struct sockaddr_in cli;
	struct socket *sk;
	
	sk = xmalloc(sizeof(struct socket *));
	
	fd = socket(AF_INET,SOCK_STREAM,0);
	if(sk-fd < 0) {
		printf("socket error \n");
		return NULL;
	}
	/* resolve name */
	h = gethostbyname(server);
	if(!h) {
		perrx("The hostname couln't be resolved\n");
		return NULL;
	}
	
	pptr = h->h_addr_list;
	for(;*pptr;pptr++) {
		inet_ntop(h->h_addrtype,*pptr,ip,sizeof(ip));
		break;
	}
	
	memset(&cli,0,sizeof(struct sockaddr_in));
	sk->sk_cli.sin_port = htons(port);
	sk->sk_cli.sin_family = AF_INET;
	sk->sk_cli.sin_addr.s_addr = inet_addr(ip);
	
	/* fill socket buffer  */
	sk->sk_port = port;
	sk->sk_ip = htonl(sk->sk_cli.sin_addr.s_addr);
	ret = connect(fd,(const struct sockaddr*)&sk->sk_cli,sizeof(struct sockaddr));
	sk->sk_fd = fd;
	if(ret == -1) {
		perrx("Connect()");
		return NULL;
	}
	
	return sk;
}

void etn_sock_close(struct socket *sk)
{
	if(!sk)
		return;
	
	close(sk->sk_fd);
}
void banner(const char *arg)
{
	printfd(1,"Usage : \n"
	       "%s <server IP> <server port> <locale IP> <key> [MTU]\n"
	       ,arg
		);
	exit(0);
}

int etn_setup_promisc(struct netdev *nd)
{
	char buf[1024]={0};
	struct ifconf ifc;
	struct ifreq *ifr;
	int if_cnt;
	int yes;
	struct sockaddr_ll sll;

	/* set netlink socket */
	nd->nd_fd = socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
	if(nd->nd_fd == -1) {
		perrx("socket:PF_PACKET");
		return -1;
	}
	
	memset(&ifc,0,sizeof(ifc));
	memset(&ifr,0,sizeof(ifr));
	
	ifc.ifc_len = sizeof(buf);
	ifc.ifc_buf = buf;
	
	if(ioctl(nd->nd_fd,SIOCGIFCONF,&ifc) < 0) {
		perrx("ioctl:SIOCGIFCONF");
		return -1;
	}
	/* list all network interfaces 
	   then look for the desired one */
	ifr = ifc.ifc_req;
	if_cnt =ifc.ifc_len / sizeof(struct ifreq);

	ifr = lookup_dev(ifr,&if_cnt,nd);
	if(ifr == NULL) {
		perrx("Couldn't get device name \n");
		return -1;
	}
#ifdef IFCONF
	printfd(2,"interface index : %d\n",ifr->ifr_ifindex);
	printfd(2,"interface address : "IPFMT"\n",
	       ipfmt((int)(((struct sockaddr_in *)&ifr->ifr_addr)->sin_addr.s_addr)));
	printfd(2,"interface netmask : "IPFMT"\n",
		ipfmt((int)(((struct sockaddr_in *)&ifr->ifr_netmask)->sin_addr.s_addr)));
#endif
	/* make sure that the interface is UP & RUNNING */
	ifr->ifr_flags |= IFF_PROMISC;
	ifr->ifr_flags |= IFF_UP |IFF_RUNNING;
	if(ioctl(nd->nd_fd, SIOCSIFFLAGS, ifr) < 0) {
		perrx("ioctl:SIOCGIFCONF");
		return -1;
	}
	
	/* get interface index */
	if (ioctl(nd->nd_fd,SIOCGIFINDEX,ifr)==-1) {
		perrx("SIOCGIFINDEX");
	}
	
	if (setsockopt(nd->nd_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == -1) {
		perrx("setsockopt:SO_REUSEADDR");
		return -1;
	}
	/* No need for this
	if (setsockopt(nd->nd_fd, SOL_SOCKET, SO_BINDTODEVICE, ifr->ifr_name, IFNAMSIZ-1) == -1)	{
		perrx("SO_BINDTODEVICE");
		return -1;
	}
	*/
	
	memset(&sll,0,sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = ifr->ifr_ifindex;
	sll.sll_protocol = htons(ETH_P_ALL);
	
	if(bind(nd->nd_fd,(struct sockaddr*)&sll,sizeof(sll)) == -1) {
		perrx("bind");
		return -1;
	}
	
	nd->nd_ops->xmit(nd,NULL);
	
	return 0;
}

struct ifreq * lookup_dev(struct ifreq *ifr,int *count,struct netdev *nd)
{
	int i;
	struct ifreq *ifr_tmp;
	in_addr_t ip1;
	
	for(i=0;i<*count; i++) {
		ifr_tmp = &ifr[i];
		ip1 = ((struct sockaddr_in *)&ifr_tmp->ifr_addr)->sin_addr.s_addr;
		if(ip1 == nd->nd_ipaddr) {
			printf("ifname : %s\n",ifr_tmp->ifr_name);
			
			*count = i;
			return ifr_tmp;
		}
	}
	return NULL;
}

static int etn_cli_recv(struct netdev *nd,struct socket *sk)
{
	int ret;
	struct mbuf mb_d,mb;
	int maxfd;
	fd_set in;
	unsigned int nbytes;
	struct rc4_context ctx;
	
	rc4_prepare_shared_key(&ctx,shr_key);

	mb_d.mb_data = xmalloc(IP_MAXRECV);
	mb_d.mb_len = 0;
	if(mb_d.mb_data == NULL)
		goto bad;
	
	mb.mb_data = xmalloc(IP_MAXRECV*sizeof(char));
	mb.mb_len = 0;
	if(mb.mb_data == NULL)
		goto bad;

	FD_ZERO(&in);
	maxfd = (nd->sk->sk_fd > nd->nd_fd)? nd->sk->sk_fd:nd->nd_fd;
	
	while(1) {
		FD_SET(nd->nd_fd,&in);
		FD_SET(nd->sk->sk_fd,&in);

		ret = select(maxfd+1,&in,NULL,NULL,NULL);
		if(ret == -1 || errno == EINTR)
			continue;
			
		/* we got something from device  */
		if(FD_ISSET(nd->nd_fd,&in)) {
			mb_d.mb_len = recvfrom(nd->nd_fd,mb_d.mb_data,IP_MAXPACKET,0,NULL,NULL);
			if(mb_d.mb_len == -1) {
				perrx("etn_cli_recv:recv");
				goto bad;
			}
			rc4_cipher(mb_d.mb_data,mb_d.mb_len,&ctx);			
			ret = send(nd->sk->sk_fd,mb_d.mb_data,mb_d.mb_len,0);
			if(ret == -1) {
				perrx("etn_cli_recv:send");
				goto bad;
			}
		}
		/* we got something from socket */
		if(FD_ISSET(nd->sk->sk_fd,&in)) {
			mb.mb_len = recv(nd->sk->sk_fd,mb.mb_data,IP_MAXRECV,0);
			if(mb.mb_len == -1) {
				perrx("recv_sock_handler:recv");
				goto bad;
			}
			rc4_cipher(mb.mb_data,mb.mb_len,&ctx);
			nbytes = sendto(nd->nd_fd,mb.mb_data,mb.mb_len,0,NULL,0);
			
			if(nbytes == -1) {	
				perrx("recv_sock_handler:send");
				//goto bad;
			}
			
		}
		
		
	}
	
bad:
	if(mb_d.mb_data)
		free(mb.mb_data);
	exit(0);
	return -1;
}

static int etn_cli_exit(struct netdev *nd)
{
	if(nd) 
		free(nd);
	return 0;
}

