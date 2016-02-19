bin_PROGRAMS = pivots pivotc

AM_CFLAGS=-ggdb -DUSE_SSL -DUSE_POLL -I../include 

LIBS := $(LIBS) -lpthread -lcrypto -lssl -ldl

pivotc_CFLAGS=-ggdb -Wall -Wimplicit-function-declaration -DUSE_SSL -DUSE_POLL -I../include 

pivots_SOURCES = pivots.c utils.c crypto.c

pivotc_SOURCES = pivotc.c utils.c crypto.c
#AM_LDFLAGS= -lcrypto -lssl -ldl
