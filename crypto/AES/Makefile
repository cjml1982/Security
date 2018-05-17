CXXFLAGS = -g -O2 -std=gnu++11
LNK_OPT = -g -L/usr/lib/ -lssl
LIBS=-lpthread -lz -lssl -lcrypto -lndn-cxx
COFLAGS=-O2
CWFLAGS=-Wall -Wno-deprecated-declarations -std=c++11
CIFLAGS=-I./gsoap -I./gsoap/plugin
CMFLAGS=-DWITH_COOKIES -DWITH_GZIP -DWITH_OPENSSL
CFLAGS= $(CWFLAGS) $(COFLAGS) $(CIFLAGS) $(CMFLAGS)
  
all:  
	rm -f codec  
	g++ -g $(CFLAGS) aes_codec.cpp -o codec $(LNK_OPT) $(LIBS)
  
clean:  
	rm -f codec 
