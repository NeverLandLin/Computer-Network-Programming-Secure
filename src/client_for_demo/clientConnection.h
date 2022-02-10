#ifndef _CLIENT_CONNECTION
#define _CLIENT_CONNECTION

#include<sys/socket.h>
#include<arpa/inet.h>   //inet_addr
#include<signal.h>
#include<iostream>
using namespace std;

#define True 1
#define False 0

class ClientConnection{
	public:
		ClientConnection();
		ClientConnection(const char*,const char*);
		~ClientConnection();
		void execute();
		bool checkConnection();
		static void* connectP2P(void *);
		void test(){cout << "1";};
	private:
		// server IP address and port number of server when connection is established
		char serverIP[20] = {0};
		char serverPort[20] = {0};

		int socket_desc;
    	struct sockaddr_in server;

		// My IP address and port number of client after login
		char myName[20] = {0};
		// char* myIP;
		// char* myPort;

		// int socket_desc_me;
		// struct sockaddr_in me;

		bool haveLogin;
		bool threadCreated;
		bool isExit;


		pthread_t threadP2P;
		int* new_sock;

		struct sigaction sigIntHandler;

		
		void printMessage(const char*);
		bool checkSendFormat(const char*);
		bool checkSendType(const char*);
		void toUpper(char*);
		void cleanReturnList(char*, char**);
		bool checkLoginUserRegister(const char*);
		void getUserInfo();
		bool paymentToOther (const char*, const char*, int);
};

#endif