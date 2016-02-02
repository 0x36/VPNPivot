CC=gcc
SRC=$(wildcard *.c)
OBJ=$(SRC:.c=.o)
DEP=MF.dep
CFLAGS=-ggdb -lpthread -lssl -lcrypto  -O2 -Wall -Wimplicit-function-declaration -DUSE_SSL -DUSE_POLL
Q=@
BINSRV=pivots
BINCLI=pivotc
OB= crypto.o utils.o
all:$(BINSRV) $(BINCLI)

$(BINSRV):$(OB) pivots.o
	$(Q)echo "  [BIN] $@"
	@$(CC) -o $@ $^ etn.h $(CFLAGS)

$(BINCLI):pivotc.o $(OB)
	$(Q)echo "  [BIN] $@"
	@$(CC) -o $@ $^ $(CFLAGS)

%.o:%.c
	@echo "  [CC] $@"	
	@$(CC) -c $< $(CFLAGS)

clean_obj:
	@rm -rf $(OBJ)

clean: clean_obj
	@echo "  [RM] *~ $(DEP)"
	@$(Q)rm -rf *~
	$(Q)rm -rf $(DEP)
	@echo "  [RM] $(BINSRV) $(BINCLI)"
	$(Q)rm -rf $(BINSRV)
	$(Q)rm -rf $(BINCLI)
ifdef ($(wildcard Makefile.dep,))
include $(DEP)
endif
