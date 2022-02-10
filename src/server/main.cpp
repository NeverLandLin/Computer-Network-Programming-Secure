#include"server.h"
#include<pthread.h>
#include<iostream>
using namespace std;

bool checkFormat(const int argc, char* argv[]){
	if(argc < 3) {
		cerr << "Please execute the server with format:\n './bin/server [port number] -a'\n";
		return false;
	}
	if(argc > 3){
		cerr << "Warning! the argument should be './bin/server [port number] -a', arguments after fourth argument will be skipped\n";
		cerr << "as your input, the server port number will be " << argv[1] << "\n"; 
	}

	return true;
}

int main (int argc , char *argv[]) {
	if(!checkFormat(argc, argv))
		return 0;
	Server server(argv[1], argv[2]);
	return 0;	
}

