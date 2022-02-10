#ifndef _USER
#define _USER

#include <string>

using namespace std;



class User{
	public:
		User();
		User(const char*,const char*);
		~User();
	private:
		// server IP address and port number of server when connection is established
		char serverIP[20] = {0};
		char serverPort[20] = {0};

		int socket_desc;
    	struct sockaddr_in server;

		vector<string> Online
};

#endif