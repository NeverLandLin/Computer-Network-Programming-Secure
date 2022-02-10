#include"server.h"
#include"../utility.h"
#include<stdio.h>
#include<string.h>
#include<stdlib.h>	
#include<sys/socket.h>
#include<arpa/inet.h>
#include<unistd.h>	
#include<pthread.h> //for threading , link with lpthread
#include<vector>
#include<queue>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
using namespace std;
#define MAX_SEND_SIZE 1024
#define MAX_BUFFER_SIZE 1024
#define MAX_ONLINE_NUM 1000
#define MAX_IP_SIZE 32
#define MAX_PORT_NUM 6
#define MAX_LISTEN_NUM 3
#define MAX_PATH_LENGTH 100



void my_handler(int s){
	// printf("\nCaught signal %d\n",s);
	if(s != 2)
		return;
	printf("\n******Session******\n");
	printf("Server closed\n");
	printf("\nBye!");
	fflush(stdout);
	// sleep(1);
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



// the type of isOnline is integer, -1 means offline, 1 means online
// so if (user.isOnline), 
// it will be true, since if(-1) returns true
void Server::toUpper (char* string){
	int length = strlen(string);
	for(int i = 0 ; i < length; i++){
		string[i] = toupper(string[i]);
	}

}


vector<int> socketServer;
vector<struct sockaddr_in> clientList;
RSA* rsaPrivateKey;
queue<int> waitingQueue;
int threadNum = 0;
int connectNum = 0; 

void * Server::connection_handler(void* server){
	//Get the socket descriptor
	int number = threadNum - 1;
	int sock = socketServer[number];
	struct sockaddr_in client = clientList[number];
	char* clientIP = inet_ntoa(client.sin_addr);
	int clientPort = ntohs(client.sin_port);	
	
 	// SSL library init
	SSL_library_init();
	// load in all SSL alg.
	OpenSSL_add_all_algorithms();	
	// load in all SSL error msg
	SSL_load_error_strings();
	// make a SSL_CTX, with SSL v2 v3 both including
	SSL_CTX* ctx;
	// reinterpret_cast<Server*>(server)-> ctx = SSL_CTX_new(SSLv23_server_method());	
	ctx = SSL_CTX_new(SSLv23_server_method());

	if(ctx == NULL){
		ERR_print_errors_fp(stdout);
		exit(1);
	}

	// 這些要在創建 ssl = SSL_new(ctx)之前
	// SSL_CTX_set_options(ctx, SSL_OP_SINGLE_DH_USE);
	int use_cert = SSL_CTX_use_certificate_file(ctx, "./src/server/server.crt" , SSL_FILETYPE_PEM);
	int use_prv = SSL_CTX_use_PrivateKey_file(ctx, "./src/server/server.key", SSL_FILETYPE_PEM);

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

	SSL* ssl;
	ssl = SSL_new(ctx);
	SSL_set_fd(ssl, sock);

	if(SSL_accept(ssl) == -1){
		ERR_print_errors_fp(stderr);
	}

	ShowCerts(ssl);
	// reinterpret_cast<Server*>(server)->ShowCerts(ssl);

	bool flag = false;
	if(connectNum >= MAX_LISTEN_NUM){
		flag = true;
		waitingQueue.push(number);
		char* msg = "Await for server...\nthere is too many client connect to the server\nYou are in the waiting queue\nIt will direct to server if it's your turn!";
		SSL_write(ssl, "Await for server...\nthere is too many client connect to the server\nYou are in the waiting queue\nIt will direct to server if it's your turn!", strlen(msg));
		// write(sock, "Await for server...\nthere is too many client connect to the server\nYou are in the waiting queue\nIt will direct to server if it's your turn!", strlen("Await for server...\n there is too many client connect to the server\n You are in the waiting queue\nIt will direct to server if it's your turn!\n"));
		while(connectNum >= MAX_LISTEN_NUM || waitingQueue.front() != number){			
			// printf("51 %d\n", waitingQueue.front() );
			// No sleep will no use
			sleep(2);
			continue;
		}
		if(connectNum < MAX_LISTEN_NUM && waitingQueue.front() == number){
			waitingQueue.pop();
			connectNum += 1;
			printLightGreen();
			printf("\n******************************************\n");
			printf("New connection accepted\n");
			printf("Client IP   : %s\n",  inet_ntoa(client.sin_addr));
			printf("Client Port : %d\n\n", ntohs(client.sin_port));
			printf("Now is %d / %d clients connected\n\n", connectNum, MAX_LISTEN_NUM);
			printf("And Below are the online member list:\n");
			char* onlineUser = reinterpret_cast<Server*>(server)->getOnlineUser();
			// printf("%s\n", onlineUser);
			printf("\n******************************************\n\n");
			printDefault();	
			// write(sock, "Connect OK!", strlen("Connect OK!"));
			SSL_write(ssl, "Connect OK!", strlen("Connect OK!"));			
		}
	}
	if(flag == false){
		connectNum += 1;
		// write(sock, "Connect OK!", strlen("Connect OK!"));
		SSL_write(ssl, "Connect OK!", strlen("Connect OK!"));
		printLightGreen();
		printf("\n******************************************\n");
		printf("New connection accepted\n");
		printf("Client IP   : %s\n",  inet_ntoa(client.sin_addr));
		printf("Client Port : %d\n\n", ntohs(client.sin_port));
		printf("Now is %d / %d clients connected\n\n", connectNum, MAX_LISTEN_NUM);
		printf("And Below are the online member list:\n");
		char* onlineUser = reinterpret_cast<Server*>(server)->getOnlineUser();
		// printf("%s\n", onlineUser);
		printf("\n******************************************\n\n");
		printDefault();		
	}


	int read_size;
	char *message , client_message[2000];
	// TODO: remember userName
	char* userName;

	while(1){
		if(read_size= SSL_read(ssl, client_message, 2000) > 0)
		{
			printCyan();
			printf("\n---------------------\n");
			printf("Display message from clients for demo:\n");
			printf("%s\n", client_message);
			printf("\n---------------------\n");		
			printDefault();
			// reinterpret_cast<Server*>(server)->processMessage(client_message, sock, clientIP, clientPort);
			reinterpret_cast<Server*>(server)->processMessageWithSSL(client_message, ssl, clientIP, clientPort);
			memset( client_message, '\0', 2000 );
		}
		else
        {
            ERR_print_errors_fp(stderr);
        }	
	}

	SSL_shutdown(ssl);
	SSL_free(ssl);
	close(sock);
	//沒加會segmentfault
	pthread_exit(NULL);	
}


Server::Server(){
	printf("Please execute the client with format './bin/server [port number] -a'\n");
}

Server::Server(const char* serverPort, const char* mode){
	int socket_desc , new_socket , c;
	struct sockaddr_in server , client;
	char *message;
	char cwd[MAX_PATH_LENGTH] = {0};
	char* temp;

		// load private key
		FILE* fp = fopen( "./src/server/server.key", "rb");
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

    // if (!ssl) {
    //     printf("Error creating SSL.\n");
    //     log_ssl();
    //     return -1;
    // }




	// // load server certificate , and pass to client with it's public key
	// getcwd(cwd, MAX_PATH_LENGTH);
	// // if(strlen(cwd) == 1)
	// // 	cwd[0] = '\0';

	// // int SSL_CTX_use_certificate_file(SSL_CTX *ctx, const char *file, int type);	
	// if(SSL_CTX_use_certificate_file(ctx, temp=strcat(cwd, "cacert.pem"), SSL_FILETYPE_PEM) <= 0){
    // 	ERR_print_errors_fp(stdout);
  	//  	exit(1);		
	// }

	// // load private key
	// getcwd(cwd, MAX_PATH_LENGTH);
	// // if(strlen(cwd) == 1)
	// // 	cwd[0] = '\0';
	// if(SSL_CTX_use_PrivateKey_file(ctx, temp=strcat(cwd, "server_privatekey.pem"), SSL_FILETYPE_PEM) <= 0){
	// 	ERR_print_errors_fp(stdout);
	// 	exit(1);
	// }

	// // check private key
	// if (!SSL_CTX_check_private_key(ctx)){
	// 	ERR_print_errors_fp(stdout);
	// 	exit(1);
	// }

	//Create socket
	socket_desc = socket(AF_INET , SOCK_STREAM , 0);

	if (socket_desc == -1)
	{
		printf("23Could not create socket\n");
	}
	
	//Prepare the sockaddr_in structure
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = INADDR_ANY;
	server.sin_port = htons( atoi(serverPort) );
	
	//Bind
	if( bind(socket_desc,(struct sockaddr *)&server , sizeof(server)) < 0)
	{
		puts("34bind failed\n");
	}
	
	//Listen
	listen(socket_desc , MAX_LISTEN_NUM);
	
	//Accept and incoming connection
	puts("Waiting for incoming connections...\n");
	c = sizeof(struct sockaddr_in);
	vector<pthread_t> threads;

	// catch ctrl-c
	sigIntHandler.sa_handler = my_handler;
	sigemptyset(&sigIntHandler.sa_mask);
	sigIntHandler.sa_flags = 0;
	sigaction(SIGINT, &sigIntHandler, NULL);


	int ssl_err = 0;
	// while(ssl_err = SSL_accept(ssl)){
	while(new_socket = accept(socket_desc, (struct sockaddr *)&client, (socklen_t*)&c))
	{
		// 去 thread 那邊做
		// SSL* ssl = SSL_new(ctx);
		// SSL_set_fd(ssl, new_socket);
		// ssl_err = SSL_accept(ssl);
		pthread_t sniffer_thread ;
		threads.push_back(sniffer_thread);
		socketServer.push_back(new_socket);
		clientList.push_back(client);
		threadNum += 1;
		// connectNum += 1;
		if( pthread_create( &threads[threadNum - 1] , NULL ,  &Server::connection_handler , this) < 0)
		{
			
			printf("58thread creation error\n");
		}		
	}
	
	// if (new_socket<0)
	// {
	// 	perror("accept failed");
	// 	// return 1;
	// }
	
	// return 0;
}


Server::~Server(){
	for(int i = 0; i < users.size(); i++){
		delete[] users[i].name;
		delete[] users[i].IP;
	}
}

void Server::processMessage(const char* recvData, int socket, char* clientIP,int& clientPort){
 	const char delim[] = "#";
	char string[MAX_SEND_SIZE] = {0};
	strcpy(string, recvData);
	
	char* start = strtok(string, delim);
	char* mid = strtok(nullptr, delim);
	// char* mid = new char[16];
	// mid = strtok(nullptr, delim);
	char* end = strtok(nullptr, delim);
#ifdef DEBUG
	printf("+++++++++++++\n");
	printf("%s\n", clientIP);
	printf("%d\n", clientPort);
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
			printYellow();
			printf("'REGISTER#<UserAccountName>'\n");
			printDefault();			
			write(socket , "230 INPUT_FORMAT_ERROR\n", strlen("230 INPUT_FORMAT_ERROR\n"));
			// return false;
		}
		//註冊後未打名字
		else if ( strcmp(start,"REGISTER") == 0 && mid == nullptr){
			printf("\nPlease enter your user name.\n");
			write(socket , "230 INPUT_FORMAT_ERROR\n", strlen("230 INPUT_FORMAT_ERROR\n"));
			// return false;
		}	
		// 打了正確指令: REGISTER
		else if ( strcmp(start,"REGISTER") == 0 && mid != nullptr){
				if(!userHasRegister(mid)){
					printf("\nRegisteration OK\n");
					write(socket , "100 OK\n", strlen("100 OK\n"));
					
					//If not use dynamic memory, the char array will disappear after
					char* temp = new char[16]{0};
					strcpy(temp, mid);
					char* tempIP = new char[MAX_IP_SIZE]{0};
					strcpy(tempIP, clientIP);

					User newUser = {temp, tempIP, clientPort, 10000, -1, -1};
					users.push_back(newUser);
				}
				else{
					printRed();
					printf("\nThe username exists\n");
					printDefault();
					write(socket , "210 FAIL\n", strlen("210 FAIL\n"));					
				}
			return;
		}
		// LIST 大小寫錯誤
		// else if ( strcmp(start, "List") != 0 && strcmp(upperString, "LIST") == 0 ){
		// 	cout << "\nThis should be in format : \n";
		// 	printYellow();
		// 	printf("'List'\n");
		// 	printDefault();
		// 	write(socket , "230 INPUT_FORMAT_ERROR\n", strlen("230 INPUT_FORMAT_ERROR\n"));	
		// 	return;
		// }
		// LIST
		else if ( strcmp(start, "List") == 0){
			// 這台機器沒登入
			if(!IPPortIsOnline(clientIP, clientPort)){
				printf("\nThis command should be connducted after login\n");
				write(socket , "Please login first\n", strlen("Please login first\n"));	
			}
			else{
				// printf("204\n");
				char* message =  getOnlineList(clientIP, clientPort);
				// write(socket , message, strlen(message));	
				write(socket , message, MAX_SEND_SIZE);
				delete[] message;
			}
			return ;
		}		
		// Exit 大小寫錯誤
		// else if ( strcmp(start, "Exit") != 0 && strcmp(upperString, "EXIT") == 0){
		// 	cout << "\nThis should be in format : \n";
		// 	printYellow();
		// 	printf("'Exit'\n");
		// 	printDefault();
		// 	// return false;
		// }
		// Exit成功
		else if ( strcmp(start, "Exit") == 0){
			userExit(clientIP, clientPort);
			write(socket , "Bye\n", strlen("Bye\n"));	
			// connectNum -= 1;
			return;
		}
		// 登入用到server port
		else if (mid!= nullptr && strcmp(mid, serverPort) == 0 ){
			// printRed();
			// printf("\nThe port number %s is occupied by server.\n", serverPort);
			// printDefault();
			write(socket , "Please Change a port number\n\n", strlen("Please Change a port number\n\n"));
			// return false;
		}
		// TODO: I want to check the duplicate login, but "List" is a operation after login
		// 成功登入
		else if (mid != nullptr  && end == nullptr && atoi(mid) != 0){
			if(userHasRegister(start)){
				printf("\nLogin ok\n");
				userLogin(start,clientIP , atoi(mid), socket);
				char* message =  getOnlineList(clientIP, atoi(mid));
				write(socket , message, strlen(message));	
				clientPort = atoi(mid);
			}
			else{
				printRed();
				printf("\nLogin Fail\n");
				printDefault();
				write(socket , "220 AUTH_FAIL\n", strlen("220 AUTH_FAIL\n"));
			}
		}
		// else if (mid != nullptr  && end == nullptr && atoi(mid) == 0 && !haveLogin){
		// 	printf("\nIf you want to login, please enter :\n");
		// 	printYellow();
		// 	printf("'<UserAccountName>#<PortNumber>'\n");
		// 	printDefault();
		// 	// return false;
		// }		
		// 因為這裡包含P2P，所以 client 的 port number 也必須是 1024 ~ 65535間
		// else if (mid != nullptr  && end == nullptr && (atoi(mid) < 1024 || atoi(mid) > 65535) && !haveLogin){
		// 	printRed();
		// 	printf("\nSince this contains the p2p service, the port number of client have to range from 1024 to 65535\n");
		// 	printDefault();
		// 	// return false;
		// }
		// else if(mid != nullptr  && end == nullptr &&  atoi(mid) > 0 && haveLogin){
		// 	printRed();
		// 	printf("\nYou have logined, if you want to change the port number, Please exit and relogin\n");
		// 	printDefault();
		// 	// return false;
		// }
		// //未登入想轉帳
		// else if (start != nullptr && mid != nullptr && end != nullptr && atoi(mid) <= 0 && !haveLogin){
		// 	printRed();
		// 	printf("\nTo conduct payment, please login first\n");
		// 	printDefault();
		// 	// return false;
		// }
		// 登入了，但想冒充別人轉帳
		// else if (start != nullptr && mid != nullptr && end != nullptr && strcmp(start, myName) != 0){
		// 	printRed();
		// 	printf("\n冒充別人是不好的行為歐歐歐歐~~\n");
		// 	printDefault();
		// 	// return false;
		// }
		// 自己轉給自己
		// else if(start != nullptr && mid != nullptr && end != nullptr && strcmp(end, myName) == 0){
		// 	printRed();
		// 	printf("\nThe payment tansferred from you to yourself is not allowed. \n");
		// 	printDefault();
		// 	// return false;
		// }
		// // 付負數的錢或中間亂打
		// else if (start != nullptr && mid != nullptr && end != nullptr && atoi(mid) <= 0){
		// 	printRed();
		// 	printDefault();
		// 	// return false;
		// }
		// //p2p payment 成功
		else if (start != nullptr && mid != nullptr && end != nullptr && atoi(mid) != 0){
			payment(start, mid, end, clientIP, clientPort);
			// but the payer don't need to communicate the server, so return false
			// return false;
		}
		else{
			printRed();
			printf("\nInput format error\n");
			printDefault();
			write(socket , "230 INPUT_FORMAT_ERROR\n", strlen("230 INPUT_FORMAT_ERROR\n"));
		}
	}	
}

void Server::processMessageWithSSL(const char* recvData, SSL* ssl, char* clientIP,int& clientPort){
 	const char delim[] = "#";
	char string[MAX_SEND_SIZE] = {0};
	strcpy(string, recvData);
	
	char* start = strtok(string, delim);
	char* mid = strtok(nullptr, delim);
	// char* mid = new char[16];
	// mid = strtok(nullptr, delim);
	char* end = strtok(nullptr, delim);
#ifdef DEBUG
	printf("+++++++++++++\n");
	printf("%s\n", clientIP);
	printf("%d\n", clientPort);
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
			printYellow();
			printf("'REGISTER#<UserAccountName>'\n");
			printDefault();			
			// write(socket , "230 INPUT_FORMAT_ERROR\n", strlen("230 INPUT_FORMAT_ERROR\n"));
			SSL_write(ssl, "230 INPUT_FORMAT_ERROR\n", strlen("230 INPUT_FORMAT_ERROR\n"));
			// return false;
		}
		//註冊後未打名字
		else if ( strcmp(start,"REGISTER") == 0 && mid == nullptr){
			printf("\nPlease enter your user name.\n");
			// write(socket , "230 INPUT_FORMAT_ERROR\n", strlen("230 INPUT_FORMAT_ERROR\n"));
			SSL_write(ssl, "230 INPUT_FORMAT_ERROR\n", strlen("230 INPUT_FORMAT_ERROR\n"));			
			// return false;
		}	
		// 打了正確指令: REGISTER
		else if ( strcmp(start,"REGISTER") == 0 && mid != nullptr){
				if(!userHasRegister(mid)){
					printf("\nRegisteration OK\n");
					// write(socket , "100 OK\n", strlen("100 OK\n"));
					SSL_write(ssl, "100 OK\n", strlen("100 OK\n"));
					//If not use dynamic memory, the char array will disappear after
					char* temp = new char[16]{0};
					strcpy(temp, mid);
					char* tempIP = new char[MAX_IP_SIZE]{0};
					strcpy(tempIP, clientIP);

					User newUser = {temp, tempIP, clientPort, 10000, -1, -1};
					users.push_back(newUser);
				}
				else{
					printRed();
					printf("\nThe username exists\n");
					printDefault();
					// write(socket , "210 FAIL\n", strlen("210 FAIL\n"));					
					SSL_write(ssl, "210 FAIL\n", strlen("210 FAIL\n"));
				}
			return;
		}
		// LIST 大小寫錯誤
		// else if ( strcmp(start, "List") != 0 && strcmp(upperString, "LIST") == 0 ){
		// 	cout << "\nThis should be in format : \n";
		// 	printYellow();
		// 	printf("'List'\n");
		// 	printDefault();
		// 	write(socket , "230 INPUT_FORMAT_ERROR\n", strlen("230 INPUT_FORMAT_ERROR\n"));	
		// 	return;
		// }
		// LIST
		else if ( strcmp(start, "List") == 0){
			// 這台機器沒登入
			if(!IPPortIsOnline(clientIP, clientPort)){
				printf("\nThis command should be connducted after login\n");
				// write(socket , "Please login first\n", strlen("Please login first\n"));	
				SSL_write(ssl, "Please login first\n", strlen("Please login first\n"));
			}
			else{
				// printf("204\n");
				char* message =  getOnlineList(clientIP, clientPort);
				// write(socket , message, strlen(message));
				// cout << "606 " << message;
				// cout << "\n+++++++++++\n";
				// cout << "608" << strlen(message);
				// cout << "\n+++++++++++\n";
				SSL_write(ssl,  message, strlen(message));					
			}
			return ;
		}		
		// Exit 大小寫錯誤
		// else if ( strcmp(start, "Exit") != 0 && strcmp(upperString, "EXIT") == 0){
		// 	cout << "\nThis should be in format : \n";
		// 	printYellow();
		// 	printf("'Exit'\n");
		// 	printDefault();n");
		// 	// return false;
		// }
		// Exit成功
		else if ( strcmp(start, "Exit") == 0){
			userExit(clientIP, clientPort);
			// write(socket , "Bye\n", strlen("Bye\n"));
			SSL_write(ssl, "Bye\n", strlen("Bye\n"));	
			connectNum -= 1;
			return;
		}
		// 登入用到server port
		else if (mid!= nullptr && strcmp(mid, serverPort) == 0 ){
			// printRed();
			// printf("\nThe port number %s is occupied by server.\n", serverPort);
			// printDefault();
			// write(socket , "Please Change a port number\n\n", strlen("Please Change a port number\n\n"));
			SSL_write(ssl, "Please Change a port number\n\n", strlen("Please Change a port number\n\n"));	
			// return false;
		}
		// TODO: I want to check the duplicate login, but "List" is a operation after login
		// 成功登入
		else if (mid != nullptr  && end == nullptr && atoi(mid) != 0){
			if(userHasRegister(start)){
				printf("\nLogin ok\n");
				// userLogin(start,clientIP , atoi(mid), socket);
				userLoginWithSSL (start,clientIP , atoi(mid), ssl);
				char* message =  getOnlineList(clientIP, atoi(mid));
				// write(socket , message, strlen(message));
				cout << "644 " << message;
				SSL_write(ssl,  message, strlen(message));		
				clientPort = atoi(mid);
			}
			else{
				printRed();
				printf("\nLogin Fail\n");
				printDefault();
				// write(socket , "220 AUTH_FAIL\n", strlen("220 AUTH_FAIL\n"));
				SSL_write(ssl, "220 AUTH_FAIL\n", strlen("220 AUTH_FAIL\n"));	
			}
		}
		// //p2p payment 成功
		else if (start != nullptr && mid != nullptr && end != nullptr && atoi(mid) != 0){
			payment(start, mid, end, clientIP, clientPort);
			// but the payer don't need to communicate the server, so return false
			// return false;
		}
		else{
			// printRed();
			// printf("\nInput format error\n");
			// printDefault();
			// write(socket , "230 INPUT_FORMAT_ERROR\n", strlen("230 INPUT_FORMAT_ERROR\n"));
			// SSL_write(ssl, "230 INPUT_FORMAT_ERROR\n", strlen("230 INPUT_FORMAT_ERROR\n"));	
			
			// 解密
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
			int response = RSA_private_decrypt(RSA_size(rsaPrivateKey), (unsigned char*)recvData,
						(unsigned char*)decryptMessage, rsaPrivateKey, RSA_PKCS1_PADDING);
			// cout << "429\n"  << response <<endl;			
			if (response < 0) {
				char buf[128];
				cerr << "RSA_public_encrypt: " << ERR_error_string(ERR_get_error(), buf) << endl;
			}
			
			// else if( send(socket_desc_p2p , transMessage , strlen(transMessage) , 0) < 0)
			// if(SSL_write(sslTemp, transMessage , strlen(transMessage)) < 
			// cout << "437\n" << decryptMessage << endl;
			// 加密完的長度是120，不會跟原本一樣
			// cout << "439\n" << strlen((char*)decryptMessage) << endl;
			printCyan();
			printf("*****************\n");
			printf("The encrypted message from client(payee) :\n\n");
			printf("	%s \n\n", recvData);
			printf("The decrypted message :\n\n");
			printf("	%s \n", decryptMessage);
			printf("*****************\n");		
			printDefault();

			// if(SSL_write(sslTemp, encryptMessage , strlen((char*)encryptMessage) ) < 0)
			// {
			// 	cout << "2" << endl;
			// 	cout << ("\n590Send failed\n Maybe server is still unconnected, please check your server is online,\n");
			// 	return false;
			// }
			// printf("389 %s\n" , recvData);
			start = strtok(decryptMessage, delim);
			mid = strtok(nullptr, delim);
			end = strtok(nullptr, delim);

 			if (start != nullptr && mid != nullptr && end != nullptr && atoi(mid) != 0)	
				payment(start, mid, end, clientIP, clientPort);
			else{
				printRed();
				printf("\nInput format error\n");
				printDefault();
				// write(socket , "230 INPUT_FORMAT_ERROR\n", strlen("230 INPUT_FORMAT_ERROR\n"));
				SSL_write(ssl, "230 INPUT_FORMAT_ERROR\n", strlen("230 INPUT_FORMAT_ERROR\n"));

			}

		}
	}	
}


bool Server::userIsOnline(const char* name){
	for(int i = 0; i < users.size(); i++){
		if(strcmp(name, users[i].name) == 0)
			if(users[i].isOnline != -1)
				return true;		
	}
	return false;
}

bool Server::IPPortIsOnline(const char* IP, int Port){
	// printUsers();
	// printf("\n346 %s\n", IP);
	// printf("347 %d\n\n\n", Port);
	for(int i = 0; i < users.size(); i++){
		if(strcmp(IP, users[i].IP) == 0 && (Port) == users[i].port)
			if(users[i].isOnline != -1)
				return true;		
	}
	// printf("333finish\n");
	return false;
}


bool Server::userHasRegister(const char* name){
	// printUsers();
	for(int i = 0; i < users.size(); i++){
		// printf("%s\n", name);
		// printf("%s\n", users[i].name);
		if(strcmp(name, users[i].name) == 0)
			return true;	
	}
	return false;
}

char* Server::intToChar(int number){
	// printf("360 %d\n", number);
	if( number >= 10000 && number < 100000){
		// need '/0'
		char* num = new char[6]{0};
		// TODO 為何 strlen(num)
		memset(num, 0, strlen(num));
		int digit1 = (number / 10000);
		int digit2 = number / 1000 - digit1 * 10;
		int digit3 = number / 100 - digit1 * 100 - digit2 * 10;
		int digit4 = number / 10 - digit1 * 1000 - digit2 * 100 - digit3 * 10;
		int digit5 = number % 10;
		num[0] = digit1 + '0';
		num[1] = digit2 + '0';
		num[2] = digit3 + '0';
		num[3] = digit4 + '0';
		num[4] = digit5 + '0';
		// printf("367 %d\n", strlen(num));
		// printf("367 %s\n", num);
		return num;
	}
	else if( number >= 1000){
		char* num = new char[5]{0} ;
		memset(num, 0, strlen(num));
		int digit1 = number / 1000;
		int digit2 = number / 100 - digit1 * 10;
		int digit3 = number / 10 - digit1 * 100 - digit2 * 10;
		int digit4 = number % 10;
		num[0] = digit1 + '0';
		num[1] = digit2 + '0';
		num[2] = digit3 + '0';
		num[3] = digit4 + '0';
		// printf("376 %d\n", strlen(num));
		// printf("376 %s\n", num);
		return num;
	}
	else if( number >= 100){
		char* num = new char[4]{0} ;
		memset(num, 0, strlen(num));
		int digit1 = number / 100 ;
		int digit2 = number / 10 - digit1 * 10;
		int digit3 = number % 10;
		num[0] = digit1 + '0';
		num[1] = digit2 + '0';
		num[2] = digit3 + '0';
		// printf("384 %d\n", strlen(num));
		// printf("384 %s\n", num);
		return num;
	}
	else if( number >= 10){
		char* num = new char[3]{0} ;
		memset(num, 0, strlen(num));
		num[0] = (number / 10) + '0';
		num[1] = (number % 10) + '0';
		// printf("391 %d\n", strlen(num));
		// printf("391 %s\n", num);
		return num;
	}
	else if( number >= 0){
		char* num = new char[2]{'\0'};
		memset(num, 0, strlen(num));
		num[0] = (number) + '0';
		// printf("397 %d\n", strlen(num));
		// printf("397 %s\n", num);
		return num;
	}
}

char* Server::getOnlineList(const char* userIP, int userPort){
	//char message[MAX_SEND_SIZE] = {0};
	char* message = new char[MAX_SEND_SIZE]{0};
	memset(message, 0, MAX_SEND_SIZE);
	// for(int i = 0 ; i < MAX_SEND_SIZE; i++)
	// 	message[i] = '/0';
	char onlineList[MAX_SEND_SIZE] = {0};
	int onlineNum = 0;
	for(int i = 0; i < users.size(); i++){
		if(users[i].isOnline == 1){
			onlineNum += 1;
			if(strcmp(userIP, users[i].IP) == 0 && (userPort) == users[i].port){
				char* temp =  intToChar(users[i].accountBalance);
				strcat(message, temp);
				strcat(message, "\n");
				delete[] temp;
			}
			strcat(onlineList, users[i].name);
			strcat(onlineList, "#");
			strcat(onlineList, users[i].IP);
			strcat(onlineList, "#");
			char* temp1 =  intToChar(users[i].port);
			strcat(onlineList, temp1);
			delete[] temp1;			
			strcat(onlineList, "\n");	
		}
	}
	strcat(message, "public key");
	// strcat(message, publicKey.c_str());
	// strcat(message,"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsuuR1KnUfzNAacBL9DiEUvZ" );
	// strcat(message,"MIIBIjANBg" );
	strcat(message, "\n");
	char* temp2 =  intToChar(onlineNum);
	// cout << temp2 << endl;
	strcat(message, temp2);
	delete[] temp2;
	strcat(message, "\n");
	strcat(message, onlineList);
	// cout << onlineList << endl;
	// cout << "792\n" << message;
	// 8
	// cout << "793\n" << sizeof(message);
	// 39
	// cout << "794\n" << strlen(message);
	return message;
}

char* Server::getOnlineUser(){
	//char message[MAX_SEND_SIZE] = {0};
	char onlineList[MAX_SEND_SIZE] = {0};
	int onlineNum = 0;
	for(int i = 0; i < users.size(); i++){
		if(users[i].isOnline == 1){
			onlineNum += 1;
			strcat(onlineList, users[i].name);
			strcat(onlineList, "#");
			strcat(onlineList, users[i].IP);
			strcat(onlineList, "#");
			char* temp1 =  intToChar(users[i].port);
			strcat(onlineList, temp1);
			delete[] temp1;			
			strcat(onlineList, "\n");	
		}
	}
	printf("%s\n", onlineList);
	// 會return NULL
	return onlineList;
}


void Server::userLogin(const char* name, const char* IP, const int port, int clientSocketFD){
	for(int i = 0; i < users.size(); i++){
		if(strcmp(name, users[i].name) == 0){
			memset( users[i].IP , '\0', strlen(users[i].IP) );
			strcpy(users[i].IP, IP);
			users[i].port = port;
			users[i].isOnline = 1;
			users[i].socketFD = clientSocketFD;
			return ;
		}	
	}
}

void Server::userLoginWithSSL(const char* name, const char* IP, const int port, SSL* ssl){
	for(int i = 0; i < users.size(); i++){
		if(strcmp(name, users[i].name) == 0){
			memset( users[i].IP , '\0', strlen(users[i].IP) );
			strcpy(users[i].IP, IP);
			users[i].port = port;
			users[i].isOnline = 1;
			// users[i].socketFD = clientSocketFD;
			users[i].ssl = ssl;
			return ;
		}	
	}
}


void Server::userExit(const char* IP, const int port){
	for(int i = 0; i < users.size(); i++){
		if(strcmp(IP, users[i].IP) == 0 && port == users[i].port){
			users[i].isOnline = -1;
			users[i].socketFD = -1;
		}	
	}
}

void Server::printUsers(){
	printf("\n**************DEBUG****************\n");
	printf("Registered User Num : %d\n", users.size());
	for(int i = 0; i < users.size(); i ++){
		printf("%s %s %d %d\n", users[i].name , users[i].IP, users[i].port ,users[i].isOnline);
	}
	printf("\n**************DEBUG****************\n");
}

void Server::payment(const char* payer, const char* money, const char* payee, const char* clientIP, const int clientPort){
	bool flag = false;
	for(int i = 0; i < users.size(); i++){
		if(strcmp(payee, users[i].name) != 0)
			continue;
		// 送訊息來的人要是收錢的人
		if(strcmp(clientIP, users[i].IP) == 0 && clientPort == users[i].port){
			// printf("find i!\n");
			for(int j = 0; j < users.size(); j++){
				// printf("%d\n", j);
				if(strcmp(payer, users[j].name) == 0){
					// printf("find j!\n");
					//自己轉給自己
					if(i == j)
						break;
					//錢不夠還硬要轉
					if(users[j].accountBalance < atoi(money)){
						break;
					}
					users[i].accountBalance += atoi(money);
					users[j].accountBalance -= atoi(money);
					// write(users[j].socketFD , "Transfer OK!\n", strlen("Transfer OK!\n"));
					SSL_write(users[j].ssl , "Transfer OK!\n", strlen("Transfer OK!\n"));
					flag = true;
					printf("\nTransfer OK!\n");
					break;
				}
			}
		}	
	}
	if(flag == false){
		for(int j = 0; j < users.size(); j++){
			if(strcmp(payer, users[j].name) == 0){
				// write(users[j].socketFD , "Transfer Fail!\n", strlen("Transfer Fail!\n"));
				SSL_write(users[j].ssl , "Transfer Fail!\n", strlen("Transfer Fail!\n"));				
				printRed();
				printf("\nTransfer Fail!\n");
				printDefault();
				flag = true;
				break;
			}
		}		
	}
}