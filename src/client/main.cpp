#include"clientConnection.h"
#include<iostream>
using namespace std;

bool checkFormat(const int argc, char* argv[]){
	if(argc < 3) {
		cerr << "Please execute the client with format:\n './bin/client [server IP address] [port number]'\n";
		return false;
	}
	if(argc > 3){
		cerr << "Warning! the argument should be './bin/client [server IP address] [port number]', arguments after fourth argument will be skipped\n";
		cerr << "as your input, the server IP address will be " << argv[1] << ", and the port number will be " << argv[2] << "\n"; 
	}

	return true;
}
void* test(void* i){
	cout << (char*)(i);
}

int main (int argc , char *argv[]) {
	if(!checkFormat(argc, argv))
		return 0;
	ClientConnection connection(argv[1], argv[2]);
	// if(connection.checkConnection() == true)
	connection.execute();

	return 0;	
}


