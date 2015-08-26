CC=gcc
SRC=$(wildcard *.c)
OBJ=$(SRC:.c=.o)
DEP=MF.dep
CFLAGS=-ggdb -lpthread -Wall -O2
Q=@
BINSRV=vpnp_server
BINCLI=vpnp_client
OB= utils.o crypto.o
all:$(BINSRV) $(BINCLI)

$(BINSRV):vpnp_server.o $(OB)
	$(Q)echo "  [BIN] $@"
	@$(CC) -o $@ $^ $(CFLAGS)

$(BINCLI):vpnp_client.o $(OB)
	$(Q)echo "  [BIN] $@"
	@$(CC) -o $@ $^ $(CFLAGS)

%.o:%.c
	@echo "  [CC] $@"	
	$(Q)$(CC) -c $< $(CFLAGS)

clean_obj:
	@rm -rf $(OBJ)

clean: clean_obj
	@echo "  [RM] *~ $(DEP)"
	$(Q)rm -rf *~
	$(Q)rm -rf $(DEP)
	@echo "  [RM] $(BINSRV) $(BINCLI)"
	$(Q)rm -rf $(BINSRV)
	$(Q)rm -rf $(BINCLI)
ifdef ($(wildcard Makefile.dep,))
include $(DEP)
endif
