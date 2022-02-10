#include"clientConnection.h"
#include "../utility.h"
#include <bits/stdc++.h>
#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<unistd.h>
#include<signal.h>
#include<iostream>
#include<thread>
#include<pthread.h> 
#include <errno.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <fstream>
#define MAX_SEND_SIZE 1024
#define MAX_BUFFER_SIZE 1024
#define MAX_ONLINE_NUM 10
#define MAX_IP_SIZE 32
#define MAX_PORT_NUM 6

//易錯點
// 1.使用strcpy(temp, string)時，需要宣告 temp 長度，char* temp 是會報錯的 

// 待做
// P2P送完記得要recv
// 如何偵測登入指令
// 後登入的轉帳才有用，可能是卡在迴圈裡?

SSL* ssl;
int socket_test = 0;
// ca Name
string caNum = "";
RSA * rsaPrivateKey;
RSA * rsaPublicKey;

RSA* meprikey;
RSA* mepubkey;
void my_handler(int s){
	// printf("\nCaught signal %d\n",s);
	if(s != 2)
		return;
	printf("\n******Session******\n");
	printf("Connection closed\n");
	printf("\nBye!");
	char argument[5] = {0};
	argument[0] = 'E';
	argument[1] = 'x';
	argument[2] = 'i';
	argument[3] = 't';

	// if( send(socket_test , argument , strlen(argument) , 0) < 0)
	if( SSL_write(ssl , argument , strlen(argument) ) < 0)	
	{
		cout << ("\n463Send failed\n Maybe server is still unconnected, please check your server is online,\n");

	}

	char list[MAX_BUFFER_SIZE] ={0};
	// recv(socket_test, list, sizeof(list), 0 );	
	SSL_read(ssl, list, sizeof(list));
	exit(1); 
	return;
}
void ShowCerts(SSL * ssl)
{
  X509 *cert;
  char *line;

  cert = SSL_get_peer_certificate(ssl);
  if (cert != NULL) {
    printf("Digital certificate information:\n");
    line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
    printf("Certificate: %s\n", line);
    free(line);
    line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
    printf("Issuer: %s\n", line);
    free(line);
    X509_free(cert);
  }
  else
    printf("No certificate information!\n");
}


ClientConnection::ClientConnection(){
	printf("Please execute the client with format './bin/client [server IP address] [port number]'\n");
}

ClientConnection::ClientConnection(const char* IP, const char* port){
	try
	{
		socket_desc = socket(AF_INET , SOCK_STREAM , 0);
		socket_test = socket_desc;
		if (socket_desc == -1)
    	{
        	cout << ("Could not create socket");
    	}
		
		server.sin_addr.s_addr = inet_addr(IP);
		server.sin_family = AF_INET;
		server.sin_port = htons(atoi(port));

		SSL_CTX *ctx;
		SSL_library_init();
		// load in all SSL alg.
		OpenSSL_add_all_algorithms();	
		// load in all SSL error msg
		SSL_load_error_strings();
		// make a SSL_CTX, with SSL v2 v3 both including
		ctx = SSL_CTX_new(SSLv23_client_method());
		if(ctx == NULL){
			ERR_print_errors_fp(stderr);
			exit(1);
		}

		//check file
		fstream file;      
		file.open("numberlist.txt", ios::in);
		if(!file){
			file.close();
			file.open("numberlist.txt", ios::out);
			file << 2;
			caNum = "1";
			file.close();
		}
		else{
			int temp;
			file >> temp;
			caNum = to_string(temp);
			file.close();
			file.open("numberlist.txt", ios::out);
			temp += 1;
			file << temp;
			file.close();
		}
		//private key and certificate
		string a = "openssl req -x509 -new -nodes -sha256 -utf8 -days 3650 -newkey rsa:2048 -keyout " +caNum +"_private.key -out "+caNum+ ".crt -config ssl.conf";
		system(a.c_str());
		string b = "openssl rsa -in " + caNum+ "_private.key -pubout -out " + caNum +"_public.key";
		system(b.c_str());
		// string c = "openssl x509 -inform der -in " +caNum+".crt -pubkey -noout > "+ caNum+"_public.key";
		// system(c.c_str());
		// 要在 ssl = SSL_new 之前
		// SSL_CTX_set_options(ctx, SSL_OP_SINGLE_DH_USE);
		// int use_cert = SSL_CTX_use_certificate_file(ctx, "./src/client/client.crt" , SSL_FILETYPE_PEM);
		int use_cert = SSL_CTX_use_certificate_file(ctx, (caNum + ".crt").c_str() , SSL_FILETYPE_PEM);
		if(use_cert <= 0){
			ERR_print_errors_fp(stderr);
			exit(1);
		}
		// int use_prv = SSL_CTX_use_PrivateKey_file(ctx, "./src/client/client.key", SSL_FILETYPE_PEM);
		int use_prv = SSL_CTX_use_PrivateKey_file(ctx, (caNum + "_private.key").c_str(), SSL_FILETYPE_PEM);
		if(use_prv <= 0){
			ERR_print_errors_fp(stderr);
			exit(1);
		}
		int check = SSL_CTX_check_private_key(ctx);
		if(!check){
			fprintf(stderr, "Private key does not match the public certificate\n");
			exit(1);
		}	

		if (connect(socket_desc , (struct sockaddr *)&server , sizeof(server)) < 0)
		{
			printf("connect error, please check your input IP and port.\n");
			printf("Or maybe server is offline.");
			exit(1);
			isExit = true;
		}		
		
		
		ssl = SSL_new(ctx);
		SSL_set_fd(ssl, socket_desc);

		if(SSL_connect(ssl)<0)
		{
			printf("141\n");
			ERR_print_errors_fp(stderr);
			// isExit = true;
		}
		else{	
			printf("Connected with% sencryption \n", SSL_get_cipher(ssl));
			ShowCerts(ssl);
		}

		// load private key
		FILE* fp = fopen((caNum + "_private.key").c_str(), "rb");
		if(!fp){
			printf("184 no Key, Please check");
			exit(1);
		}
        rsaPrivateKey = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
        if(rsaPrivateKey == NULL)
        {
            ERR_load_crypto_strings();
            char err[1024];
            char* errret = ERR_error_string(ERR_get_error(), err);
            printf("KBE_RSA::loadPrivate: PEM_read_RSAPrivateKey error(%s : %s)\n",
                errret, err);
            fclose(fp);
            exit(1);
        }
	    else
      	  fclose(fp);
		// FILE* ff = fopen("temp_208.pem", "w");
		// PEM_write_RSAPublicKey(ff, rsaPrivateKey);
		// fclose(ff);
		// ff = fopen("temp_211.pem", "w");
		// PEM_write_RSAPrivateKey(ff, rsaPrivateKey, NULL, 0, 0, NULL, NULL);
		// fclose(ff);
		// PEM_write_RSAPrivateKey(ff, rsaPrivateKey);
		// TODO public key cannot load?
		// fp = fopen((caNum + "_public.key").c_str(), "rb");
		// if(!fp){
		// 	printf("203 no Key, Please check");
		// 	exit(1);
		// }
        // rsaPublicKey = PEM_read_RSAPublicKey(fp, NULL, NULL, NULL);
        // if(rsaPublicKey == NULL)
        // {
        //     ERR_load_crypto_strings();
        //     char err[1024];
        //     char* errret = ERR_error_string(ERR_get_error(), err);
        //     printf("KBE_RSA::loadPublic: PEM_read_RSAPublicKey error(%s : %s)\n",
        //         errret, err);
        //     fclose(fp);
        //     exit(1);
        // }
	    // else
      	//   fclose(fp);



		//connect successfully
		strcpy(serverIP, IP);
		strcpy(serverPort, port); 
		isExit = false; 
		threadCreated = false;
		haveLogin = false;

		// catch ctrl-c
		sigIntHandler.sa_handler = my_handler;
		sigemptyset(&sigIntHandler.sa_mask);
		sigIntHandler.sa_flags = 0;

		sigaction(SIGINT, &sigIntHandler, NULL);		

		while(1){
			char buffer[MAX_BUFFER_SIZE] = {0};
			int read_size = SSL_read(ssl, buffer, sizeof(buffer));
			// recv(socket_desc, buffer, sizeof(buffer), 0 );
			// printf("\n%s\n", buffer);
			if(read_size > 0)
				if(strcmp(buffer, "Connect OK!") == 0)
					break;
				else
					printf("Wait for server for it's connected too many clients.\n");
			else
      		  {
      	      ERR_print_errors_fp(stderr);
      		  }	
		}

	}
	catch(const std::exception& e)
	{
		cout << e.what() << '\n';
	}	
}

ClientConnection::~ClientConnection(){
	printf("Connection lost\n");
	// pthread_join( threadP2P , NULL);
}



void* ClientConnection::connectP2P(void* message){
	const char otherDelim[] = "#";
	char myIP [MAX_IP_SIZE] = {0};
	char myPort[MAX_PORT_NUM] = {0};
	char test [MAX_BUFFER_SIZE] = {0};
	// char* test;
	// printf("115 %s\n", (char*)message);
	// printf("115 %s\n", (char*)(message));
	// cout << "123" << endl;
	//TODO 報錯的地方
	strcpy(test, (char*)(message));
	// strcpy(test, (char*)message);
	// cout << "254" << endl;
	// printf("200 %s\n", test) ;

#ifdef DEBUG
	printf("114 %s\n", test);
	// 直接用 (char*) (message) 會出錯?
	printf("115 %s\n", (char*)message);
	printf("115 %s\n", (char*)(message));
#endif 

	char* userAccount = strtok(test, otherDelim);

	char* userIP = strtok(nullptr, otherDelim);

	char* userPort = strtok(nullptr, otherDelim);

	strcpy(myIP, userIP);

	strcpy(myPort, userPort);
	
// // #ifdef DEBUG
// 	printf("116 %s\n", userIP);
// 	printf("117 %s\n", userPort);
// // #endif
	int socket_desc_me = socket(AF_INET , SOCK_STREAM , 0);
	if (socket_desc_me == -1)
	{
		cout << ("\nCould not create Your socket\n");
	}

	// cout << "123456\n";
	
	struct sockaddr_in me;
	//Prepare the sockaddr_in structure
	me.sin_family = AF_INET;
	me.sin_addr.s_addr = INADDR_ANY;
	// me.sin_addr.s_addr = inet_addr(myIP);
	me.sin_port = htons( atoi(myPort) );
 	// SSL library init

	SSL_library_init();
	// load in all SSL alg.
	OpenSSL_add_all_algorithms();	
	// load in all SSL error msg
	SSL_load_error_strings();
	SSL_CTX *ctx;
	// make a SSL_CTX, with SSL v2 v3 both including
	//TODO
	ctx = SSL_CTX_new(SSLv23_server_method());
	if(ctx == NULL){
		ERR_print_errors_fp(stdout);
		exit(1);
	}

	// cout << "123456\n";



	// SSL_CTX_set_options(ctx, SSL_OP_SINGLE_DH_USE);
	int use_cert = SSL_CTX_use_certificate_file(ctx, (caNum + ".crt").c_str() , SSL_FILETYPE_PEM);
	if(use_cert <= 0){
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	int use_prv = SSL_CTX_use_PrivateKey_file(ctx,(caNum + "_private.key").c_str(), SSL_FILETYPE_PEM);
	if(use_prv <= 0){
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	int check = SSL_CTX_check_private_key(ctx);
	if(!check){
		fprintf(stderr, "Private key does not match the public certificate\n");
		exit(1);
	}	
	
	// cout << "123456\n";

	// SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
	// SSL_CTX_load_verify_locations(ctx, (caNum+".crt").c_str(), NULL);

	//Bind
	if( bind(socket_desc_me,(struct sockaddr *)&me , sizeof(me)) < 0)
	{
		cout << ("\nbind failed\nMaybe there is someone use this port, please change");
	}
	
	//Listen
	listen(socket_desc_me , 10);
	// printf("97\n");
	//Accept and incoming connection
	int c = sizeof(struct sockaddr_in);
	int new_socket;
	struct sockaddr_in otherClient;

	// cout << "123456\n";


	// while( (new_socket = accept(socket_desc_me, (struct sockaddr *)&otherClient, (socklen_t*)&c)) )
	int ssl_err = 0;
	// while((ssl_err = SSL_accept(sslp2p)))
	while(1)
	{
		// cout << "292" << endl;
		new_socket = accept(socket_desc_me, (struct sockaddr *)&otherClient, (socklen_t*)&c);
		// cout << "294" << endl;
		SSL* sslp2p;
		sslp2p = SSL_new(ctx);
		SSL_set_fd(sslp2p, new_socket);

		ssl_err = SSL_accept(sslp2p);
		if(ssl_err < 0)
		{
			ERR_print_errors_fp(stderr);
		}
		else{	
			printf("Connected with% sencryption \n", SSL_get_cipher(ssl));
			ShowCerts(sslp2p);
		}		
		printLightGreen();
		printf("get transaction message: \n");
		printDefault();
		char buffer[MAX_BUFFER_SIZE] ={0};

		// 注意這邊是new_socket
		// recv(new_socket, buffer, sizeof(buffer), 0 );
		SSL_read(sslp2p, buffer, sizeof(buffer));


		// 解密
		//encrypt by B's public key
		X509* server_publicKey_x509 = SSL_get_peer_certificate(ssl);
		EVP_PKEY* server_publicKey_evp = X509_get_pubkey(server_publicKey_x509);
		RSA* server_publicKey = EVP_PKEY_get1_RSA(server_publicKey_evp);
		// unsigned char* decryptMessage = (unsigned char*)malloc(RSA_size(rsaPrivateKey));
		// char* decryptMessage = (char*)malloc(RSA_size(rsaPrivateKey));
		char* decryptMessage = new char [RSA_size(rsaPrivateKey) + 1];
		memset(decryptMessage, 0, RSA_size(rsaPrivateKey) + 1);
		// unsigned char* encryptMessage = (unsigned char*)malloc(RSA_size(server_publicKey));

		// cout << "1119\n" << strlen(transMessage)<<endl ;
		// cout << "1122\n" << strlen((char*)test) << endl;
		// cout << "1122.5\n" << (char*)test << endl;
		// cout << "1123\n" << strlen(test) << endl;
		// Warning!! strlen() doesn't include '\0'
		// 成功的話，加密訊息長度會變為256位元
		// RSA_size(rsa) - 42 in doc for RSA_PKCS1_OAEP_PADDING
		int response = RSA_private_decrypt(RSA_size(rsaPrivateKey), (unsigned char*)buffer,
					(unsigned char*)decryptMessage, rsaPrivateKey, RSA_PKCS1_PADDING);
		if (response < 0) {
			char buf[128];
			cerr << "RSA_public_encrypt: " << ERR_error_string(ERR_get_error(), buf) << endl;
		}
		
		// else if( send(socket_desc_p2p , transMessage , strlen(transMessage) , 0) < 0)
		// if(SSL_write(sslTemp, transMessage , strlen(transMessage)) < 
		printCyan();
		printf("*****************\n");
		printf("The encrypted message from payer :\n\n");
		printf("	%s \n\n", buffer);
		printf("The decrypted message :\n\n");
		printf("	%s \n\n", decryptMessage);
		printf("*****************\n\n");
		// cout << "437\n" << decryptMessage << endl;
		printDefault();
		// 加密完的長度是120，不會跟原本一樣
		// cout << "439\n" << strlen((char*)decryptMessage) << endl;
		// if(SSL_write(sslTemp, encryptMessage , strlen((char*)encryptMessage) ) < 0)
		// {
		// 	cout << "2" << endl;
		// 	cout << ("\n590Send failed\n Maybe server is still unconnected, please check your server is online,\n");
		// 	return false;
		// }
		// printf("389 %s\n" , buffer);


		// unsigned char* encryptMessage = (unsigned char*)malloc(RSA_size(b_publicKey));
		// if(SSL_write(sslTemp, transMessage , strlen(transMessage)) < 0)
		char* encryptMessage = (char*)malloc(RSA_size(server_publicKey));
		memset(encryptMessage, 0, RSA_size(server_publicKey));
		unsigned char* test;
		


		// cout << "1123\n" << strlen(test) << endl;
		// Warning!! strlen() doesn't include '\0'
		// 成功的話，加密訊息長度會變為256位元
		response = RSA_public_encrypt((strlen(decryptMessage)+1) * sizeof(char), (unsigned char*)decryptMessage,
		// int response = RSA_public_encrypt(sizeof ((unsigned char*)transMessage), (unsigned char*)transMessage,
					(unsigned char*)encryptMessage, server_publicKey, RSA_PKCS1_PADDING);
		// cout << "463\n"  << response <<endl;			
		if (response < 0) {
			char buf[128];
			cerr << "RSA_public_encrypt: " << ERR_error_string(ERR_get_error(), buf) << endl;
		}
		printCyan();
		printf("*****************\n");
		printf("The encrypted message payer(this client) generate:\n\n");
		printf("	%s \n\n", encryptMessage);
		printf("*****************\n");
		printDefault();
		// cout << "467 \n" << encryptMessage;
		// else if( send(socket_desc_p2p , transMessage , strlen(transMessage) , 0) < 0)
		// if(SSL_write(sslTemp, transMessage , strlen(transMessage)) < 
		// cout << "1124\n" << encryptMessage << endl;
		// 加密完的長度是120，不會跟原本一樣
		// cout << "1125\n" << strlen((char*)encryptMessage) << endl;

		// 中間一定要用 (char*)encryptMessage
		// if(SSL_write(sslTemp, (char*)encryptMessage , strlen((char*)encryptMessage) ) < 0)
		// {
		// 	cout << "2" << endl;
		// 	cout << ("\n590Send failed\n Maybe server is still unconnected, please check your server is online,\n");
		// 	return false;
		// }

		if(SSL_write(ssl, (char*)encryptMessage, response) < 0 ){
		// if( send(socket_test , buffer , strlen(buffer) , 0) < 0){
			cout << ("\n176Send failed\n Maybe server is still unconnected, please check your server is online,\n");
			continue;
		}

		//轉完帳之後，要先收回server的return，不然會卡到下一次
		// char buffer2[MAX_BUFFER_SIZE] = {0};
		// TODO : ./server1206 is no return !! ./server may return "Transfer OK" and "Transfer Fail" 
		// recv(socket_test, buffer2, sizeof(buffer2), 0 );
		printDefault();
		printf("\n==================\n\n");
		printf("Please enter your command, or quit by enter 'Exit' :\n\n> ");
		// printf("_______________\n");
		// printf("%s\n", buffer2);
		// printf("_______________\n");
		close(new_socket);
	}

	if (new_socket<0)
	{
		perror("accept failed");
	}
	
	puts("Connection accepted");
	SSL_CTX_free(ctx);	
	void* nothing;
	return nothing;
}


bool ClientConnection::checkConnection(){
	try{
		// if( send(socket_desc , "\n" , strlen("\n") , 0) < 0)
		if(SSL_write(ssl, "\n",  strlen("\n")) < 0)
		{
			cout << ("\n\nConnection Fail, Please check your server online in the 8888 port before restart the client.\n\n");
			return false;
		}
		return true;
	}
	catch(const exception& e){
		cout << e.what() << '\n';
	}
	return true;
}

void ClientConnection::execute(){
	while(!isExit){	
		try
		{
			printf("\n==================\n\n");
			printf("Please enter your command, or quit by 'Exit' :\n\n> ");
			char argument [MAX_SEND_SIZE] = {0};
			scanf("%s", argument);
			// printf("%s\n", argument);
			if(checkSendFormat(argument)){
				

				// if user input 'Exit' wrong, we can give him/her a chance to cancel 'Exit' transmission
				if(!checkSendType(argument))
					continue;
				
				// if( send(socket_desc , argument , strlen(argument) , 0) < 0)
				if(SSL_write(ssl, argument , strlen(argument))  < 0)
				{
					cout << ("\n176Send failed\n Maybe server is still unconnected, please check your server is online,\n");
					continue;
				}
				
				char buffer[MAX_BUFFER_SIZE] ={0};

				// Prototype of recv()
				// ssize_t recv(int sockfd, void *buf, size_t len, int flags);
				// recv(socket_desc, buffer, sizeof(buffer), 0 );
				SSL_read(ssl, buffer, sizeof(buffer));

				printCyan();
				printf("\n-----------------------------\n");
				printf("Display returns from server for demo:\n");
				printf("%s\n", buffer);
				printf("\n-----------------------------\n");
				printDefault();
				
				printMessage(buffer);
				
				if(haveLogin && !threadCreated){
					threadCreated = true;
					
					getUserInfo();	
				}
			}
		}
		catch(const exception& e)
		{
			cout << e.what() << '\n';
			cout << "Please execute the client with format './client [server IP address] [port number]'\n\n";
		}	
	}
	SSL_shutdown(ssl);
	SSL_free(ssl);
}

void ClientConnection::printMessage(const char* serverReturn){
	// for(int i = 0; i < strlen(serverReturn); i++)
	// 	cout << int(serverReturn[i])<< endl;
#ifdef DEBUG
	cout << "\n====\n";
	cout << serverReturn;
	cout << "\n====\n";
#endif
	// Input format error
	// of no use
	if( strcmp(serverReturn, "230 Input format error\n230 Input format error\n") == 0){
		cout << "\nPlease Check your input format\n\n";
		cout << "There is some operations for clients:\n\n";
		cout << "1. register in server:\n";
		cout << "   REGISTER#<UserAccountName>\n\n";
		cout << "2. login your account:\n";
		cout << "   <UserAccountName>#<portNum>\n\n";
		cout << "3. get your account balance and online user list(after login):\n";
		cout << "   List\n\n";
		cout << "4. Logout and break the connection\n";
		cout << "   Exit\n\n";
		cout << "5. micropayment transaction between clients(after login):\n";
		cout << "   <MyUserAccountName>#<payAmount>#<PayeeUserAccountName>\n\n";
	}
	else if( strcmp(serverReturn, "230 Input format error\nPlease login first\n") == 0){
		printRed();
		cout << "\nYou should login to do this.\n\n";
		printDefault();
		cout << "#  login your account:\n";
		printYellow();
		cout << "   <UserAccountName>#<portNum>\n\n";
		printDefault();
	}
	else if (strcmp(serverReturn, "100 OK\n") == 0){
		cout << "Register Successfully!\n";
		cout << "Now you can login with this account\n\n";
	}
	else if (strcmp(serverReturn, "210 FAIL\n") == 0){
		printRed();
		cout << "Register Error. \n";
		cout << "There may someone with the same name, please change your account name\n\n";
		printDefault();
	}
	else if (strcmp(serverReturn, "220 AUTH_FAIL\n") == 0){
		printRed();
		cout << "Login Error. \n";
		cout << "The account name is not registered, please check the name. \n\n";
		printDefault();
	}
	else if (strcmp(serverReturn, "Bye\n") == 0){
		close(socket_desc);
	}
	//List
	//TODO
	else if (strlen(serverReturn) > 32){
		haveLogin = true;
		printCyan();
		//cout << serverReturn ;
		printDefault();
	}
}

bool ClientConnection::checkSendFormat (const char* sendData){
 	const char delim[] = "#";
	char string[MAX_SEND_SIZE] = {0};
	strcpy(string, sendData);
	
	char* start = strtok(string, delim);
	char* mid = strtok(nullptr, delim);
	char* end = strtok(nullptr, delim);
#ifdef DEBUG
	printf("+++++++++++++\n");
	printf("%s\n", start);
	printf("%s\n", mid);
	printf("%s\n", end);
	printf("+++++++++++++\n");
#endif
	if(start != nullptr){
		char upperString[MAX_SEND_SIZE]= {0};
		strcpy(upperString, start);
		toUpper(upperString);
		//是打註冊，但註冊不是全大寫
		if( strcmp(start,"REGISTER") != 0 && strcmp(upperString, "REGISTER") == 0){
			cout << "\nThis should be in format : \n";
			printYellow();
			printf("'REGISTER#<UserAccountName>'\n");
			printDefault();			
			return false;
		}
		//註冊後未打名字
		else if ( strcmp(start,"REGISTER") == 0 && mid == nullptr){
			printf("\nPlease enter your user name.\n");
			return false;
		}	
		//不接受數字名字
		else if ( strcmp(start,"REGISTER") == 0 && (atoi(mid)) !=0){
			printf("\nThe name must be all english character\n");
			return false;
		}
		//成功註冊
		else if ( strcmp(start,"REGISTER") == 0){
			return true;
		}
		// LIST 大小寫錯誤
		else if ( strcmp(start, "List") != 0 && strcmp(upperString, "LIST") == 0 ){
			cout << "\nThis should be in format : \n";
			printYellow();
			printf("'List'\n");
			printDefault();
			return false;
		}
		// LIST但尚未登入
		else if ( strcmp(start, "List") == 0 && !haveLogin){
			printf("\nThis command should be connducted after login\n");
			return false;
		}		
		// LIST 成功
		else if ( strcmp(start, "List") == 0 && haveLogin){
			return true;
		}
		// Exit 大小寫錯誤
		else if ( strcmp(start, "Exit") != 0 && strcmp(upperString, "EXIT") == 0){
			cout << "\nThis should be in format : \n";
			printYellow();
			printf("'Exit'\n");
			printDefault();
			return false;
		}
		// Exit成功
		else if ( strcmp(start, "Exit") == 0){
			return true;
		}
		// 登入用到server port
		else if (mid!= nullptr && strcmp(mid, serverPort) == 0 ){
			cout << "\nThe port number " << serverPort << " is occupied by server.\n";
			cout << "Please Change a port number\n\n";
			return false;
		}
		// TODO: I want to check the duplicate login, but "List" is a operation after login
		//	成功登入
		else if (mid != nullptr  && end == nullptr && atoi(mid) >= 1024 && atoi(mid) <= 65535 && !haveLogin){
	 		strcpy(myName, start);
			// haveLogin = true;
			return true;
		}
		else if (mid != nullptr  && end == nullptr && atoi(mid) == 0 && !haveLogin){
			printf("\nIf you want to login, please enter :\n");
			printYellow();
			printf("'<UserAccountName>#<PortNumber>'\n");
			printDefault();
			return false;
		}		
		// 因為這裡包含P2P，所以 client 的 port number 也必須是 1024 ~ 65535間
		else if (mid != nullptr  && end == nullptr && (atoi(mid) < 1024 || atoi(mid) > 65535) && !haveLogin){
			printRed();
			printf("\nSince this contains the p2p service, the port number of client have to range from 1024 to 65535\n");
			printDefault();
			return false;
		}
		else if(mid != nullptr  && end == nullptr &&  atoi(mid) > 0 && haveLogin){
			printRed();
			printf("\nYou have logined, if you want to change the port number, Please exit and relogin\n");
			printDefault();
			return false;
		}
		//未登入想轉帳
		else if (start != nullptr && mid != nullptr && end != nullptr && atoi(mid) <= 0 && !haveLogin){
			printRed();
			printf("\nTo conduct payment, please login first\n");
			printDefault();
			return false;
		}
		// 登入了，但想冒充別人轉帳
		else if (start != nullptr && mid != nullptr && end != nullptr && strcmp(start, myName) != 0){
			printRed();
			printf("\n冒充別人是不好的行為歐歐歐歐~~\n");
			printDefault();
			return false;
		}
		// 自己轉給自己
		else if(start != nullptr && mid != nullptr && end != nullptr && strcmp(end, myName) == 0){
			printRed();
			printf("\nThe payment tansferred from you to yourself is not allowed. \n");
			printDefault();
			return false;
		}
		// 付負數的錢或中間亂打
		else if (start != nullptr && mid != nullptr && end != nullptr && atoi(mid) <= 0){
			printRed();
			printf("nothing");
			printDefault();
			return false;
		}
		//p2p payment 成功
		else if (start != nullptr && mid != nullptr && end != nullptr && atoi(mid) != 0){
			paymentToOther(end, sendData, atoi(mid));
			// but the payer don't need to communicate the server, so return false
			return false;
		}
		else{
			printRed();
			printf( "\nPlease Check your input format\n\n");
			printDefault();
			printf( "There is some operations for clients:\n\n");
			
			printf( "1. register in server:\n");
				printYellow();
			printf( "   REGISTER#<UserAccountName>\n\n");
				printDefault();
			printf( "2. login your account:\n");
				printYellow();
			printf( "   <UserAccountName>#<portNum>\n\n");
				printDefault();
			printf( "3. get your account balance and online user list(after login):\n");
				printYellow();
			printf( "   List\n\n");
				printDefault();
			printf( "4. Logout and break the connection\n");
				printYellow();
			printf( "   Exit\n\n");
				printDefault();
			printf( "5. micropayment transaction between clients(after login):\n");
				printYellow();
			printf( "   <MyUserAccountName>#<payAmount>#<PayeeUserAccountName>\n\n");			
				printDefault();
		}
	}
	return false;
}


bool ClientConnection::checkSendType (const char* sendData){
	const char delim[] = "#";
	char string[MAX_SEND_SIZE] = {0};
	strcpy(string, sendData);
	char* start = strtok(string, delim); 
	char* mid = strtok(nullptr, delim);
	char* end = strtok(nullptr, delim);
#ifdef DEBUG
	printf("^^^^^^^^^^^^^^^^\n");
	printf("%s\n", start);
	printf("%s\n", mid);
	printf("%s\n", end);
	printf("^^^^^^^^^^^^^^^^\n");
#endif
	if(start != nullptr){
		char upperString[MAX_SEND_SIZE]= {0};
		strcpy(upperString, start);
		toUpper(upperString);

		if( strcmp(start,"Exit") == 0){
			bool getTrueReply = false;
			while(!getTrueReply){
				printf("Do you want to logout and terminate the client? [Y/n]\n> ");
				char check[10] = {0};
				scanf("%s", check);
				printf("\n");
				toUpper(check);
				if(strcmp(check, "YES") == 0 || strcmp(check, "Y") == 0){
					printf("Bye!\n\n");
					getTrueReply = true;
					isExit = true;
				}
				else if(strcmp(check, "NO") == 0 || strcmp(check, "N") == 0){
					printf("Ok ~ Keep enjoy the transactions\n\n");
					getTrueReply = true;
					return false;
				}
				else{
					printf("Please input 'y' or 'n' \n\n");
				}
			}
		}

	}

	return true;
}


void ClientConnection::toUpper (char* string){
	int length = strlen(string);
	for(int i = 0 ; i < length; i++){
		string[i] = toupper(string[i]);
	}

}

void ClientConnection::cleanReturnList(char* List, char** onlineTemp){
	// get List from server
	// if( send(socket_desc , "List" , strlen("List") , 0) < 0)
	if(SSL_write(ssl, "List", strlen("List")))
	{
		cout << ("\n372Send failed\n Maybe server is still unconnected, please check your server is online,\n");
		return;
	}

	char list[MAX_BUFFER_SIZE] = {0};
	SSL_read(ssl, list, sizeof(list));
	// recv(socket_desc, list, sizeof(list), 0 );
	char delim[] = "\n";
	char string[MAX_SEND_SIZE] = {0};
	strcpy(string, list);

	// Account Balance 
	char* accountBalanceTemp = strtok(string, delim); 
	int accountBalance = atoi(accountBalanceTemp);

	// Public Key
	char* serverPublicKey = strtok(nullptr, delim);
	
	// number of accounts online
	char* onlineNumTemp = strtok(nullptr, delim);
	int onlineNum = atoi(onlineNumTemp);

	// online member
	// char* onlineTemp[MAX_ONLINE_NUM] = {0};
	for(int i = 0; i < onlineNum; i++){
		onlineTemp[i] = strtok(nullptr, delim);
	}

}

bool ClientConnection::checkLoginUserRegister(const char* userName){
	// get List from server
	// if( send(socket_desc , "List" , strlen("List") , 0) < 0)
	if(SSL_write(ssl, "List", strlen("List")))
	{
		cout << ("\n405Send failed\n Maybe server is still unconnected, please check your server is online,\n");
		return false;
	}

	char list[MAX_BUFFER_SIZE] ={0};
	cout << "member finish" << endl;
	// recv(socket_desc, list, sizeof(list), 0 );
	SSL_read(ssl, list, sizeof(list));
	cout << "member finish" << endl;

	char delim[] = "\n";
	char string[MAX_SEND_SIZE] = {0};
	strcpy(string, list);
	cout << "member finish" << endl;

	// Account Balance 
	char* accountBalanceTemp = strtok(string, delim); 
	int accountBalance = atoi(accountBalanceTemp);
	cout << accountBalanceTemp << endl;

	// Public Key
	char* serverPublicKey = strtok(nullptr, delim);
	cout << serverPublicKey << endl;
	
	// number of accounts online
	char* onlineNumTemp = strtok(nullptr, delim);
	cout << onlineNumTemp << endl;
	int onlineNum = atoi(onlineNumTemp);
	cout << "member finish" << endl;
	// online member
	char* onlineTemp[MAX_ONLINE_NUM] = {0};
	for(int i = 0; i < onlineNum; i++){
		onlineTemp[i] = strtok(nullptr, delim);
	}
	cout << "member finish" << endl;
	// TODO : should bring it to a function
	// char* onlineTemp [MAX_ONLINE_NUM] = {0};
	// cleanReturnList(onlineTemp);

	char otherDelim[] = "#";
	bool find = false;
	for(int i = 0; i < onlineNum; i++){
		cout << i ;
		char* userAccount = strtok(onlineTemp[i], otherDelim);
		cout << i << endl;
		if(strcmp(userAccount, userName) == 0){
			find = true;
			return false;
		}
	}	
	cout << 1 << endl;

	return true;
}

void ClientConnection::getUserInfo(){
	if(!haveLogin){
		printRed();
		printf("To do this, You need login first\n");
		printDefault();
		return;
	}
	
	
	// get List from server
	// But C++ cannot assign string to char*
	// So I use the naive method ><
	char argument[5] = {0};
	argument[0] = 'L';
	argument[1] = 'i';
	argument[2] = 's';
	argument[3] = 't';

	// if( send(socket_desc , argument , strlen(argument) , 0) < 0)
	if( SSL_write(ssl, argument, strlen(argument)) < 0)
	{
		cout << ("\n463Send failed\n Maybe server is still unconnected, please check your server is online,\n");
		return ;
	}

	// printf("828 %s\n", argument);
	char list[MAX_BUFFER_SIZE] ={0};
	// recv(socket_desc, list, sizeof(list), 0 );
	// while(SSL_read(ssl, list, strlen(list)) <= 0){continue;};
	// SSL_read(ssl, list, strlen(list));
	// SSL_read(ssl, list, MAX_BUFFER_SIZE);
	SSL_read(ssl, list, sizeof(list));
	char delim[] = "\n";
	char string[MAX_SEND_SIZE] = {0};
	strcpy(string, list);
	// printf("835 %s\n", string);
#ifdef DEBUG
	printf("[[[[[[[[[[[[[[\n");
	printf("%s\n", string);
	printf("[[[[[[[[[[[[[[\n");
#endif
	// Account Balance 
	char* accountBalanceTemp = strtok(string, delim); 
	int accountBalance = atoi(accountBalanceTemp);

	// cout << "1012 " << accountBalance << endl;
	// Public Key
	char* serverPublicKey = strtok(nullptr, delim);
	// cout << "1015 " << serverPublicKey << endl;
	// number of accounts online
	char* onlineNumTemp = strtok(nullptr, delim);
	int onlineNum = atoi(onlineNumTemp);
	// cout << "1019 " << onlineNum << endl;

	// online member
	char* onlineTemp[MAX_ONLINE_NUM] = {0};

	
	for(int i = 0; i < onlineNum; i++){
		onlineTemp[i] = strtok(nullptr, delim);
		// cout << i << " " << onlineTemp[i];
	}
	// printf("603\n");



	const char otherDelim[] = "#";
	bool find = false;
	for(int i = 0; i < onlineNum; i++){
		//After strok, the onlineTemp[i] wiil be seperated
		// cout << "1043";
		char temp[MAX_BUFFER_SIZE] = {0};
		// cout << "1043";
		strcpy(temp, onlineTemp[i]);
		// cout << "1043";		
		char* userAccount = strtok(temp, otherDelim);
		if(strcmp(userAccount, myName) == 0){
			find = true;
			// cout << "\n1043 " << onlineTemp[i] << endl;
			//TODO
			pthread_create( &threadP2P , NULL , connectP2P , (void*)onlineTemp[i]);
			// cout << "1045";
			return;
		}
	}	
	return;
}


bool ClientConnection::paymentToOther(const char* payeeName, const char* transMessage, int payMoney){

	if(!haveLogin){
		printRed();
		printf("\nYou don't login.\n");
		printDefault();
	}

	// get List from server
	// But C++ cannot assign string to char*
	// So I use the naive method ><
	char argument[5] = {0};
	argument[0] = 'L';
	argument[1] = 'i';
	argument[2] = 's';
	argument[3] = 't';
	// if( send(socket_desc , argument , strlen(argument) , 0) < 0)
	if(SSL_write(ssl, argument, strlen(argument)) < 0)
	{
		printRed();
		printf("\n528Send failed\n Maybe server is still unconnected, please check your server is online,\n");
		
		printDefault();
		// return false;
	}

	char list[MAX_BUFFER_SIZE] ={0};
	// recv(socket_desc, list, sizeof(list), 0 );
	SSL_read(ssl, list, sizeof(list));

	char delim[] = "\n";
	char string[MAX_SEND_SIZE] = {0};
	strcpy(string, list);
	// cout << "927 " << string << endl;

	// Account Balance 
	char* accountBalanceTemp = strtok(string, delim); 
	int accountBalance = atoi(accountBalanceTemp);

	if(payMoney > accountBalance){
		printRed();
		printf("\nPlease check your account balance, you cannot pay more money than that to others.\n");
		printDefault();
		return false;
	}


	// Public Key
	char* serverPublicKey = strtok(nullptr, delim);
	
	// number of accounts online
	char* onlineNumTemp = strtok(nullptr, delim);
	int onlineNum = atoi(onlineNumTemp);

	// online member
	char* onlineTemp[MAX_ONLINE_NUM] = {0};
	for(int i = 0; i < onlineNum; i++){
		onlineTemp[i] = strtok(nullptr, delim);
	}

	const char otherDelim[] = "#";
	bool find = false;
	for(int i = 0; i < onlineNum; i++){
		char* userAccount = strtok(onlineTemp[i], otherDelim);
		if(strcmp(userAccount, payeeName) == 0){
			find = true;
			char* userIP = strtok(nullptr, otherDelim);
			char* userPort = strtok(nullptr, otherDelim);
			// cout << "949 \n";
			try
			{
				int socket_desc_p2p;
    			struct sockaddr_in otherClient;
				
				SSL_library_init();
				// load in all SSL alg.
				OpenSSL_add_all_algorithms();	
				// load in all SSL error msg
				SSL_load_error_strings();
				// make a SSL_CTX, with SSL v2 v3 both including
				SSL_CTX* ctx;
				// reinterpret_cast<Server*>(server)-> ctx = SSL_CTX_new(SSLv23_server_method());	
				ctx = SSL_CTX_new(SSLv23_client_method());

				if(ctx == NULL){
					ERR_print_errors_fp(stdout);
					exit(1);
				}
				// cout << "969\n";
				// 這些要在創建 ssl = SSL_new(ctx)之前
				// SSL_CTX_set_options(ctx, SSL_OP_SINGLE_DH_USE);
				int use_cert = SSL_CTX_use_certificate_file(ctx, (caNum + ".crt").c_str() , SSL_FILETYPE_PEM);
				int use_prv = SSL_CTX_use_PrivateKey_file(ctx, (caNum + "_private.key").c_str(), SSL_FILETYPE_PEM);
				// cout << "969\n";

				if(use_cert <= 0){
					ERR_print_errors_fp(stderr);
					exit(1);
				}
				if(use_prv <= 0){
					ERR_print_errors_fp(stderr);
					exit(1);
				}
				int check = SSL_CTX_check_private_key(ctx);
				if(!check){
					fprintf(stderr, "Private key does not match the public certificate\n");
					exit(1);
				}	

				
				// cout << "969\n";
				
				if (socket_desc_p2p == -1)
				{
					cout << ("Could not pay, please retry.\n\n");
					return false;
				}
				// printf("635%s\n", userIP);
				// printf("636%s\n", userPort);

				// TODO
				otherClient.sin_addr.s_addr = inet_addr("127.0.0.1");
				otherClient.sin_family = AF_INET;
				// otherClient.sin_addr.s_addr = inet_addr(userIP);
				otherClient.sin_port = htons(atoi(userPort));
				// otherClient.sin_port = htons(atoi(userPort));
				// cout << "969\n";

				socket_desc_p2p = socket(AF_INET , SOCK_STREAM , 0);
				if (connect(socket_desc_p2p , (struct sockaddr *)&otherClient , sizeof(otherClient)) < 0)
				{
					printRed();
					printf("connect error, please check your input IP and port.\n");
					printf("Or maybe server is offline.");
					printDefault();
					exit(1);
					isExit = true;
				}		

				// SSL_CTX_load_verify_locations(ctx, (caNum+".crt").c_str(), NULL);
				SSL* sslTemp;
				sslTemp = SSL_new(ctx);
				SSL_set_fd(sslTemp, socket_desc_p2p);


				// cout << "969\n";

				// if (connect(socket_desc_p2p , (struct sockaddr *)&otherClient , sizeof(otherClient)) < 0)
				if(SSL_connect(sslTemp) < 0)
				{
					// cout << "3" << endl;
					cout << ("connect error, please retry.\n\n");
					cout << strerror(errno) << endl;
					return false;
				}
				
				//encrypt by B's public key
				X509* b_publicKey_x509 = SSL_get_peer_certificate(sslTemp);
				// cout << "1110\n";
				EVP_PKEY* b_publicKey_evp = X509_get_pubkey(b_publicKey_x509);
				// cout << "1113\n";
				RSA* b_publicKey = EVP_PKEY_get1_RSA(b_publicKey_evp);
				// if(SSL_write(sslTemp, transMessage , strlen(transMessage)) < 0)
				// cout << "1116\n";
				FILE* ff = fopen("temp_1174.pem", "w");
				PEM_write_RSAPublicKey(ff, b_publicKey);
				fclose(ff);
				// unsigned char* encryptMessage = (unsigned char*)malloc(RSA_size(b_publicKey));
				// if(SSL_write(sslTemp, transMessage , strlen(transMessage)) < 0)
				char* encryptMessage = (char*)malloc(RSA_size(b_publicKey));
				memset(encryptMessage, 0, RSA_size(b_publicKey));
				
				// cout << "1119\n" << strlen(transMessage)<<endl ;
				// cout << "1123\n" << strlen(test) << endl;
				// Warning!! strlen() doesn't include '\0'
				// 成功的話，加密訊息長度會變為256位元
				int response = RSA_public_encrypt((strlen(transMessage)+1) * sizeof(char), (unsigned char*)transMessage,
                // int response = RSA_public_encrypt(sizeof ((unsigned char*)transMessage), (unsigned char*)transMessage,
				         (unsigned char*)encryptMessage, b_publicKey, RSA_PKCS1_PADDING);
				// cout << "1122\n"  << response <<endl;			
				if (response < 0) {
					char buf[128];
					cerr << "RSA_public_encrypt: " << ERR_error_string(ERR_get_error(), buf) << endl;
				}
				
				// else if( send(socket_desc_p2p , transMessage , strlen(transMessage) , 0) < 0)
				// if(SSL_write(sslTemp, transMessage , strlen(transMessage)) < 
				printCyan();
				printf("************\n");
				printf("The encrypted message payer(this client) generate: : \n");
				// cout << "1124\n" << encryptMessage << endl;
				printf("    %s\n", encryptMessage);
				printf("************\n\n");
				printDefault();
				// 加密完的長度是120，不會跟原本一樣
				// cout << "1125\n" << strlen((char*)encryptMessage) << endl;

				// 第三個參數一定要 用response ，而非strlen((char*)encryptMessage)!!!
				// if(SSL_write(sslTemp, (char*)encryptMessage , strlen((char*)encryptMessage) ) < 0)
				if(SSL_write(sslTemp, (char*)encryptMessage ,response ) < 0)
				{
					// cout << "2" << endl;
					cout << ("\n590Send failed\n Maybe server is still unconnected, please check your server is online,\n");
					return false;
				}

				else{
					printLightGreen();
					// printf("Transfer Ok\n\n");
					char buffer[MAX_BUFFER_SIZE] ={0};
					// Prototype of recv()
					// ssize_t recv(int sockfd, void *buf, size_t len, int flags);
					// recv(socket_desc, buffer, sizeof(buffer), 0 );
					// cout << "1" << endl;
					// 收 server 轉來的消息
					SSL_read(ssl, buffer, sizeof(buffer));
					printf("The transaction status from server: %s\n\n", buffer);
					printDefault();
				}
				// cout << "969\n";
				
				//connect successfully
				close(socket_desc_p2p);
				return true;
			}
			catch(const std::exception& e)
			{
				cout << e.what() << '\n';
				cout << "Please execute the client with format './client [server IP address] [port number]'\n";
			}	
		}
	}	

	if(!find){
		printRed();
		printf("There is no account named ' %s ' online.\n", payeeName);
		printf("Please check your input\n\n");
		printDefault();
		return false;
	}
	return true;
}