#if !defined H_ENT_H
#define H_ENT_H

#define TUNFILE		"/dev/net/tun"
#define DEFAULT_PORT	12345
#define MTU		1500

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include <errno.h>
#include <stdarg.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/time.h>

#include <netdb.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <arpa/inet.h> 
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <linux/if_tun.h>
#include <linux/if_packet.h>

#include <pwd.h>
#include <fcntl.h>
#include <unistd.h>

#define DEFAULT_SKEY	"I_Own_y0u"
struct netdev_ops;
struct socket;
struct mbuf;

struct mbuf_q *mbq;

struct netdev {
	int nd_fd;
	int nd_flags;
	u_char nd_name[256];
	in_addr_t nd_ipaddr;
	in_addr_t nd_netmask;
	u_int32_t nd_mtu;
	u_int8_t nd_hwaddr[6];
	u_int8_t *nd_owner;
	struct socket *sk;
	struct netdev_ops *nd_ops;
};

/* socket handler  */
struct socket {
	int sk_fd;
	in_addr_t sk_ip;
	u_int16_t sk_port;
	int sk_prot;
	struct sockaddr_in sk_serv;
	struct sockaddr_in sk_cli;
};

struct mbuf_q {
	struct mbuf *head,*tail;
	int qlen;
	pthread_mutex_t lock;
};
/* socket buffer  */
struct mbuf {
	struct mbuf *next,*prev;
	void *mb_data;
	unsigned int  mb_len;
	unsigned short mb_prot;			  /* packet protocol */
	short mb_type;			  /* packet type  */
	
};

struct netdev_ops {
	int (*init)(struct netdev *);
	int (*xmit)(struct netdev*,struct socket*);
	int (*exit)(struct netdev*);
};

#define ferr(fmt, args...) fprintf(stderr, fmt, ##args)

void *xmalloc(size_t);
void *xzalloc(size_t);
void perrx(char *str);
int printfd(int fd, const char *fmt, ...);

/* inline int __mbuf_queue_empty(void) */
/* { */
/* 	return mbq->head == (struct mbuf*)mbq; */
		
/* } */

struct socket *etn_sock_connect(char *,unsigned short);
void etn_sock_close(struct socket *);

struct rc4_context {
	unsigned char state[256];
	unsigned char x;
	unsigned char y;
};

#define SWAP_BYTES(x,y) char t = *(x); *(x) = *(y); *(y) = t

void rc4_key_sched(unsigned char *,unsigned int ,struct rc4_context *);
void rc4_cipher(unsigned char *,unsigned int ,struct rc4_context *);
void rc4_prepare_shared_key(struct rc4_context *,unsigned char *);

#endif	/* H_ETN_H */
