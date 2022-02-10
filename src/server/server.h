#ifndef _SERVER
#define _SERVER

#include<sys/socket.h>
#include<arpa/inet.h>   //inet_addr
#include<signal.h>
#include<iostream>
#include<string.h>
#include<vector>
#include <openssl/ssl.h>
using namespace std;


typedef struct User{
	char* name ;
	char* IP;
	int port;
	int accountBalance;
	int isOnline;

	// A#10000#B 
	// to return message to A, I have to store the socket filedescriptor of A
	int socketFD;
	SSL* ssl;
} User;

// struct onlineUser{
// 	string name ;
// 	string IP = "127.0.0.1";
// 	string port = "8888";	
// }

class Server{
	public:
		Server();
		Server(const char*,const char*);
		~Server();

	private:
		static void *connection_handler(void *);
		void processMessage(const char*, int,char*, int&);
		void processMessageWithSSL(const char*, SSL*,char*, int&);
		bool userIsOnline(const char*);
		bool IPPortIsOnline(const char*, int);
		bool userHasRegister(const char*);
		char* getOnlineList(const char*, int);
		char* getOnlineUser();
		char* intToChar(int);
		void userLogin(const char*, const char* , const int, int);
		void userLoginWithSSL(const char*, const char* , const int,SSL*);
		void userExit(const char*, const int);
		void payment(const char*, const char*, const char*, const char*, const int);
		void printUsers();
		void toUpper (char* );
		// void ShowCerts(SSL *);

		// server IP address and port number of server when connection is established
		char serverIP[20] = {0};
		char serverPort[20] = {0};

		vector<User> users;
		struct sigaction sigIntHandler;
		// SSL_CTX *ctx;
		// vector<onlineUser> onlineUsers;
		string publicKey= "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsuuR1KnUfzNAacBL9DiEUvZ/H8rALuJTq3CMMcmXwFKl3R5ztEGmXJQeI1piS/aKfADe7E3kknLVDi9gm+c8vfhqrR97W+fE0ke4OpyLPsTl/SLBi3kNHvqtb9h9bUm6OR39IY7+gIiVJIlKCvBxT8p299MOh6Od6fi1Q9jS0+6sCkzUSCiEH3v9nfad4MwmIuKB6wGRRWfYtyJoTSvrtS5uz+LSTk8VFwQiCkvpyembk7dJiBUU0bDvxIbdlor6h5Np+0ZoqF48ETT9+9kh/iNKZoC2d7ShFpbq5qNAH03k6MrngfK0hw5qmw85J4QIoqsqV3E0EeuyNKq5wVQRZQIDAQAB";
		};

#endif