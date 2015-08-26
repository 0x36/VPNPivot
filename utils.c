#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <stdarg.h>
#include <unistd.h>
#include "etn.h"

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

int printfd(int fd, const char *fmt, ...)
{
	char data[512];
	int len;
	va_list ap;
	int wr;
	va_start(ap, fmt);
	len = vsnprintf(data, 512, fmt, ap);
	va_end(ap);
	wr = write(fd, data, len);
	return wr;
}
