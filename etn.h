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
#include <sys/poll.h>

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

#include <openssl/crypto.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>

#define CHK_SSL_NULL(x) if ((x)==NULL) exit (1)
#define CHK_SSL_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stdout); exit(2); }

#define VPNP_ENC	0x1

struct netdev_ops;
struct socket;
struct mbuf;
struct mbuf_q *mbq;

/* global network device data structure */
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
#ifdef SOCK_DEBUG
	struct {
		int sk_fd;
		in_addr_t sk_ip;
		u_int16_t sk_port;
		int sk_prot;
	}ipinfo;
	/* some macro facilities */
#define ipinfo.sk_fd sfd
#define ipinfo.sk_fd ipaddr
#define ipinfo.sk_port port
#define ipinfo.sk_prot proto
#endif
	int sk_fd;
	in_addr_t sk_ip;
	u_int16_t sk_port;
	int sk_prot;
	struct sockaddr_in sk_serv;
	struct sockaddr_in sk_cli;
#define sfd	sk_fd
#define ipaddr	sk_fd	
#define sport	sk_port 
#define proto	sk_prot 
#define sserv	sk_serv 
#define scli	sk_cli	

	SSL_CTX *sk_ctx;
	const SSL_METHOD *sk_meth;
	SSL *sk_ssl;
	SSL_CTX *(*sk_ssl_init)(void);
	int (*sk_ssl_connect)(struct socket**);

	ssize_t (*sk_io_read)(struct socket *,struct mbuf*);
	ssize_t (*sk_io_write)(struct socket *,struct mbuf*);
	int (*sk_connect)(struct socket **,char*,u_short );
	int (*sk_setup_promisc)(struct netdev*);
};
/* used later within threads manipulation */
struct mbuf_q {
	struct mbuf *head,*tail;
	int qlen;
	pthread_mutex_t lock;
};
/* socket buffer */
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

/* allocate socket buffer */
struct socket *socket_alloc(void);
/* make SSL client connection */
int cr_ssl_connect(struct socket *);
/* connect into a tcp stream server */
struct socket *etn_sock_connect(char *,unsigned short);

/* connect to vpnp server */
int cl_sock_connect(struct socket **,char *,u_short);
void etn_sock_close(struct socket *);
in_addr_t __reslov_host(const char*);

/* I/O prototypes */
ssize_t read_packet(struct socket * ,struct mbuf *,size_t);
ssize_t send_packet(struct socket * ,struct mbuf *);
ssize_t get_data(int ,void *,size_t);

/* Crypto prototypes () */
SSL_CTX *cr_ssl_context(void);
SSL_CTX *cr_ssl_context_cli(void);
void cr_show_cert(SSL* );
int cr_make_cert(X509 **,EVP_PKEY **,int ,int ,int );
void cr_load_certs(SSL_CTX *,u_char *,u_char *);

#endif	/* H_ETN_H */

