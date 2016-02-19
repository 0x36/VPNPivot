#include "etn.h"


ssize_t read_packet(struct socket *sock,struct mbuf* mbuf,size_t mtu)
{
#ifdef USE_SSL
	mbuf->mb_len = SSL_read(sock->sk_ssl,mbuf->mb_data,mtu);
#else	
	mbuf->mb_len = read(sock->sk_fd,mbuf->mb_data,mtu);
#endif	/* USE_SSL */

	return mbuf->mb_len;
}

/* malloc manipulation */
void *xmalloc(size_t size)
{
	void *p = malloc(size);
	if(!p) 
		perrx("xmalloc");
	return p;
}

void *xzalloc(size_t size)
{
	void *p = calloc(1,size);
	if(!p)
		perrx("calloc");
	return p;
}
void perrx(char *str)
{
	if(errno)
		perror(str);
	else
		ferr("[ERROR] %d: %s",__LINE__,str);
}
/* I suck, FIXME */
int printfd(int fd, const char *fmt, ...)
{
	char *data;
	size_t len;
	va_list ap;
	int wr;
	
	len = strlen(fmt);
	data = (char*)xmalloc(len+1);
	memset(data,0,len+1);
	va_start(ap, fmt);
	len = vsnprintf(data, len, fmt, ap);
	va_end(ap);
	wr = write(fd, data, len);
	free(data);
	return wr;
}

struct socket * socket_alloc(void)
{
	struct socket *s;
	
	s = (struct socket *)xzalloc(sizeof(struct socket));
	if(!s)
		return NULL;
	
	return s;
	
}
