#COFLAGS=-O2
#CWFLAGS=-Wall -Wno-deprecated-declarations -std=c++11
#CIFLAGS=-I./gsoap -I./gsoap/plugin
#CMFLAGS=-DWITH_COOKIES -DWITH_GZIP -DWITH_OPENSSL
#CFLAGS= $(CWFLAGS) $(COFLAGS) $(CIFLAGS) $(CMFLAGS)

#OBJ_DIR = ./obj  
#BIN_DIR = ./bin  
SRC_DIR = ./
#OBJS = \  
#	aes_algo.o \  
#	main.o  
TARGET = main  
INC_OPT = -I./  
LNK_OPT = -lssl -lcrypto  
 

#$(OBJ_DIR)/%.o : $(SRC_DIR)/%.c  
#	gcc -g $(INC_OPT) -c -o $@ $<  
	#-rm -f aes_algo.o main.o
	#-rm -f main
main:aes_algo.o main.c
	gcc -g -o main main.c aes_algo.o $(LNK_OPT) 

aes_algo.o: aes_algo.h aes_algo.c
	gcc -g $(INC_OPT) -c aes_algo.c

#main.o: main.c 
	#gcc -g $(INC_OPT) -c main.c



#$(TARGET) : clean chkobjdir chkbindir $(OBJS)


#chkobjdir :  
#	@if test ! -d $(OBJ_DIR) ; \  
#	then \  
#	mkdir $(OBJ_DIR) ; \  
#	fi  
#chkbindir :  
#	@if test ! -d $(BIN_DIR) ; \  
#	then \  
#	mkdir $(BIN_DIR) ; \  
#	fi  
clean :  
	#-rm -f $(TARGET)  
	#-rm -rf $(OBJ_DIR)  
