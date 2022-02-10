# CC and CFLAGS are varilables
CC = g++
CFLAGS = -c -std=c++0x 
AR = ar
ARFLAGS = rcv
# -c option ask g++ to compile the source files, but do not link.
# -g option is for debugging version
# -O2 option is for optimized version
DBGFLAGS = -g -D_DEBUG_ON_
OPTFLAGS = -O2

all	: bin/client bin/client_for_demo bin/server
	@echo -n ""

# optimized version
bin/client	: clientConnection_opt.o main_client.o
			$(CC) $(OPTFLAGS) $^ -l pthread -o $@ -lssl -lcrypto 
main_client.o 	   	: src/client/main.cpp
			$(CC) $(CFLAGS) $< -l pthread -o $@ -lssl -lcrypto
clientConnection_opt.o	: src/client/clientConnection.cpp src/client/clientConnection.h src/utility.h
			$(CC) $(CFLAGS) $(OPTFLAGS) $< -l pthread -o $@ -lssl -lcrypto 


bin/client_for_demo	: clientConnection_demo_opt.o main_client_demo.o
			$(CC) $(OPTFLAGS) $^ -l pthread -o $@ -lssl  -lcrypto
main_client_demo.o 	   	: src/client_for_demo/main.cpp
			$(CC) $(CFLAGS) $< -l pthread -o $@  -lssl -lcrypto
clientConnection_demo_opt.o	: src/client_for_demo/clientConnection.cpp src/client_for_demo/clientConnection.h src/utility.h
			$(CC) $(CFLAGS) $(OPTFLAGS) $< -l pthread -o $@ -lssl -lcrypto   

bin/server	: server_opt.o main_server.o
			$(CC) $(OPTFLAGS) $^ -l pthread -o $@ -lssl -lcrypto  
main_server.o 	   	: src/server/main.cpp
			$(CC) $(CFLAGS) $< -l pthread -o $@ -lssl -lcrypto
server_opt.o	: src/server/server.cpp src/server/server.h src/utility.h
			$(CC) $(CFLAGS) $(OPTFLAGS) $< -l pthread -o $@  -lssl -lcrypto


clean:
		rm -rf *.o lib/*.a lib/*.o bin/* 

