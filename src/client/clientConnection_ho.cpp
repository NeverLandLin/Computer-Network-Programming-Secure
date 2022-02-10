#include"clientConnection.h"
#include "../utility.h"
#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<unistd.h>
#include<signal.h>
#include<iostream>
#include<thread>
#include<pthread.h> 
#include <errno.h>
#define MAX_SEND_SIZE 1024
#define MAX_BUFFER_SIZE 1024
#define MAX_ONLINE_NUM 1000
#define MAX_IP_SIZE 32
#define MAX_PORT_NUM 6


//易錯點
// 1.使用strcpy(temp, string)時，需要宣告 temp 長度，char* temp 是會報錯的 

// 待做
// P2P送完記得要recv
// 如何偵測登入指令
// 後登入的轉帳才有用，可能是卡在迴圈裡?


int socket_test = 0;


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

	if( send(socket_test , argument , strlen(argument) , 0) < 0)
	{
		cout << ("\n463Send failed\n Maybe server is still unconnected, please check your server is online,\n");

	}

	char list[MAX_BUFFER_SIZE] ={0};
	recv(socket_test, list, sizeof(list), 0 );	
	exit(1); 
	return;
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
		if (connect(socket_desc , (struct sockaddr *)&server , sizeof(server)) < 0)
		{
			printf("connect error, please check your input IP and port.\n");
			printf("Or maybe server is offline.");
			exit(1);
			isExit = true;
		}

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
			recv(socket_desc, buffer, sizeof(buffer), 0 );
			printf("\n%s\n", buffer);
			if(strcmp(buffer, "Connect OK!") == 0)
				break;
			else
				printf("Wait for server for it's connected too many clients.\n");
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
	strcpy(test, (char*)(message));

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
	
#ifdef DEBUG
	printf("116 %s\n", userIP);
	printf("117 %s\n", userPort);
#endif
	int socket_desc_me = socket(AF_INET , SOCK_STREAM , 0);
	if (socket_desc_me == -1)
	{
		cout << ("\nCould not create Your socket\n");
	}

	
	struct sockaddr_in me;
	//Prepare the sockaddr_in structure
	me.sin_family = AF_INET;
	me.sin_addr.s_addr = INADDR_ANY;
	// me.sin_addr.s_addr = inet_addr(myIP);
	me.sin_port = htons( atoi(myPort) );
	
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
	while( (new_socket = accept(socket_desc_me, (struct sockaddr *)&otherClient, (socklen_t*)&c)) )
	// while(1)
	{
		// (new_socket = accept(socket_desc_me, (struct sockaddr *)&otherClient, (socklen_t*)&c))
		printCyan();
		printf("get transaction message: \n");
		
		char buffer[MAX_BUFFER_SIZE] ={0};

		// 注意這邊是new_socket
		recv(new_socket, buffer, sizeof(buffer), 0 );
		printf("%s\n" , buffer);
		
		if( send(socket_test , buffer , strlen(buffer) , 0) < 0){
			cout << ("\n176Send failed\n Maybe server is still unconnected, please check your server is online,\n");
			continue;
		}

		//轉完帳之後，要先收回server的return，不然會卡到下一次
		// char buffer2[MAX_BUFFER_SIZE] = {0};
		// TODO : ./server1206 is no return !! ./server may return "Transfer OK" and "Transfer Fail" 
		// recv(socket_test, buffer2, sizeof(buffer2), 0 );
		printDefault();
		printf("\n==================================================\n\n");
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
	void*nothing;
	return nothing;
}


bool ClientConnection::checkConnection(){
	try{
		if( send(socket_desc , "\n" , strlen("\n") , 0) < 0)
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
			printf("\n==================================================\n\n");
			printf("Please enter your command, or quit by 'Exit' :\n\n> ");
			char argument [MAX_SEND_SIZE] = {0};
			scanf("%s", argument);
			// printf("%s\n", argument);
			if(checkSendFormat(argument)){
				

				// if user input 'Exit' wrong, we can give him/her a chance to cancel 'Exit' transmission
				// if(!checkSendType(argument))
					// continue;
				
				if( send(socket_desc , argument , strlen(argument) , 0) < 0)
				{
					cout << ("\n176Send failed\n Maybe server is still unconnected, please check your server is online,\n");
					continue;
				}
				
				char buffer[MAX_BUFFER_SIZE] ={0};

				// Prototype of recv()
				// ssize_t recv(int sockfd, void *buf, size_t len, int flags);
				recv(socket_desc, buffer, sizeof(buffer), 0 );
				
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
		exit(1);
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
		// if( strcmp(start,"REGISTER") != 0 && strcmp(upperString, "REGISTER") == 0){
		// 	cout << "\nThis should be in format : \n";
		// 	printYellow();
		// 	printf("'REGISTER#<UserAccountName>'\n");
		// 	printDefault();			
		// 	return false;
		// }
		// //註冊後未打名字
		// else if ( strcmp(start,"REGISTER") == 0 && mid == nullptr){
		// 	printf("\nPlease enter your user name.\n");
		// 	return false;
		// }	
		// //不接受數字名字
		// else if ( strcmp(start,"REGISTER") == 0 && (atoi(mid)) !=0){
		// 	printf("\nThe name must be all english character\n");
		// 	return false;
		// }
		// //成功註冊
		// else if ( strcmp(start,"REGISTER") == 0){
		// 	return true;
		// }
		// // LIST 大小寫錯誤
		// else if ( strcmp(start, "List") != 0 && strcmp(upperString, "LIST") == 0 ){
		// 	cout << "\nThis should be in format : \n";
		// 	printYellow();
		// 	printf("'List'\n");
		// 	printDefault();
		// 	return false;
		// }
		// // LIST但尚未登入
		// else if ( strcmp(start, "List") == 0 && !haveLogin){
		// 	printf("\nThis command should be connducted after login\n");
		// 	return false;
		// }		
		// // LIST 成功
		// else if ( strcmp(start, "List") == 0 && haveLogin){
		// 	return true;
		// }
		// // Exit 大小寫錯誤
		// else if ( strcmp(start, "Exit") != 0 && strcmp(upperString, "EXIT") == 0){
		// 	cout << "\nThis should be in format : \n";
		// 	printYellow();
		// 	printf("'Exit'\n");
		// 	printDefault();
		// 	return false;
		// }
		// // Exit成功
		// else if ( strcmp(start, "Exit") == 0){
		// 	return true;
		// }
		// // 登入用到server port
		// else if (mid!= nullptr && strcmp(mid, serverPort) == 0 ){
		// 	cout << "\nThe port number " << serverPort << " is occupied by server.\n";
		// 	cout << "Please Change a port number\n\n";
		// 	return false;
		// }
		// // TODO: I want to check the duplicate login, but "List" is a operation after login
		//	成功登入
		if (mid != nullptr  && end == nullptr && atoi(mid) >= 1024 && atoi(mid) <= 65535 && !haveLogin){
	 		strcpy(myName, start);
			// haveLogin = true;
			return true;
		}
		// else if (mid != nullptr  && end == nullptr && atoi(mid) == 0 && !haveLogin){
		// 	printf("\nIf you want to login, please enter :\n");
		// 	printYellow();
		// 	printf("'<UserAccountName>#<PortNumber>'\n");
		// 	printDefault();
		// 	return false;
		// }		
		// // 因為這裡包含P2P，所以 client 的 port number 也必須是 1024 ~ 65535間
		// else if (mid != nullptr  && end == nullptr && (atoi(mid) < 1024 || atoi(mid) > 65535) && !haveLogin){
		// 	printRed();
		// 	printf("\nSince this contains the p2p service, the port number of client have to range from 1024 to 65535\n");
		// 	printDefault();
		// 	return false;
		// }
		// else if(mid != nullptr  && end == nullptr &&  atoi(mid) > 0 && haveLogin){
		// 	printRed();
		// 	printf("\nYou have logined, if you want to change the port number, Please exit and relogin\n");
		// 	printDefault();
		// 	return false;
		// }
		// //未登入想轉帳
		// else if (start != nullptr && mid != nullptr && end != nullptr && atoi(mid) <= 0 && !haveLogin){
		// 	printRed();
		// 	printf("\nTo conduct payment, please login first\n");
		// 	printDefault();
		// 	return false;
		// }
		// // 登入了，但想冒充別人轉帳
		// else if (start != nullptr && mid != nullptr && end != nullptr && strcmp(start, myName) != 0){
		// 	printRed();
		// 	printf("\n冒充別人是不好的行為歐歐歐歐~~\n");
		// 	printDefault();
		// 	return false;
		// }
		// // 自己轉給自己
		// else if(start != nullptr && mid != nullptr && end != nullptr && strcmp(end, myName) == 0){
		// 	printRed();
		// 	printf("\nThe payment tansferred from you to yourself is not allowed. \n");
		// 	printDefault();
		// 	return false;
		// }
		// // 付負數的錢或中間亂打
		// else if (start != nullptr && mid != nullptr && end != nullptr && atoi(mid) <= 0){
		// 	printRed();
		// 	printf("\n不想轉帳就說!還打這個指令中間放奇怪的數字(字串)，你是在耍我是不是，系統很好耍嗎?小心我給你倒扣10000手續費\n");
		// 	printf("\n(助教我不是在說您QQ  您辛苦了QQ)\n");
		// 	printDefault();
		// 	return false;
		// }
		// p2p payment 成功
		else if (start != nullptr && mid != nullptr && end != nullptr && atoi(mid) != 0){
			paymentToOther(end, sendData, atoi(mid));
			// but the payer don't need to communicate the server, so return false
			return false;
		}
		// else{
		// 	printRed();
		// 	printf( "\nPlease Check your input format\n\n");
		// 	printDefault();
		// 	printf( "There is some operations for clients:\n\n");
			
		// 	printf( "1. register in server:\n");
		// 		printYellow();
		// 	printf( "   REGISTER#<UserAccountName>\n\n");
		// 		printDefault();
		// 	printf( "2. login your account:\n");
		// 		printYellow();
		// 	printf( "   <UserAccountName>#<portNum>\n\n");
		// 		printDefault();
		// 	printf( "3. get your account balance and online user list(after login):\n");
		// 		printYellow();
		// 	printf( "   List\n\n");
		// 		printDefault();
		// 	printf( "4. Logout and break the connection\n");
		// 		printYellow();
		// 	printf( "   Exit\n\n");
		// 		printDefault();
		// 	printf( "5. micropayment transaction between clients(after login):\n");
		// 		printYellow();
		// 	printf( "   <MyUserAccountName>#<payAmount>#<PayeeUserAccountName>\n\n");			
		// 		printDefault();
		// }
	}
	return true;
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
	if( send(socket_desc , "List" , strlen("List") , 0) < 0)
	{
		cout << ("\n372Send failed\n Maybe server is still unconnected, please check your server is online,\n");
		return;
	}

	char list[MAX_BUFFER_SIZE] = {0};
	recv(socket_desc, list, sizeof(list), 0 );
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
	if( send(socket_desc , "List" , strlen("List") , 0) < 0)
	{
		cout << ("\n405Send failed\n Maybe server is still unconnected, please check your server is online,\n");
		return false;
	}

	char list[MAX_BUFFER_SIZE] ={0};
	cout << "member finish" << endl;
	recv(socket_desc, list, sizeof(list), 0 );
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

	if( send(socket_desc , argument , strlen(argument) , 0) < 0)
	{
		cout << ("\n463Send failed\n Maybe server is still unconnected, please check your server is online,\n");
		return ;
	}


	char list[MAX_BUFFER_SIZE] ={0};
	recv(socket_desc, list, sizeof(list), 0 );
	char delim[] = "\n";
	char string[MAX_SEND_SIZE] = {0};
	strcpy(string, list);
#ifdef DEBUG
	printf("[[[[[[[[[[[[[[\n");
	printf("%s\n", string);
	printf("[[[[[[[[[[[[[[\n");
#endif
	// Account Balance 
	char* accountBalanceTemp = strtok(string, delim); 
	int accountBalance = atoi(accountBalanceTemp);

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
	// printf("603\n");

	// TODO : should bring it to a function
	// char* onlineTemp [MAX_ONLINE_NUM] = {0};
	// cleanReturnList(onlineTemp);

	const char otherDelim[] = "#";
	bool find = false;
	for(int i = 0; i < onlineNum; i++){
		//After strok, the onlineTemp[i] wiil be seperated
		char temp[MAX_BUFFER_SIZE] = {0};
		strcpy(temp, onlineTemp[i]);
		
		char* userAccount = strtok(temp, otherDelim);
		if(strcmp(userAccount, myName) == 0){
			find = true;
			pthread_create( &threadP2P , NULL , connectP2P , (void*)onlineTemp[i]);

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
	if( send(socket_desc , argument , strlen(argument) , 0) < 0)
	{
		printf("\n528Send failed\n Maybe server is still unconnected, please check your server is online,\n");
		// return false;
	}

	char list[MAX_BUFFER_SIZE] ={0};
	recv(socket_desc, list, sizeof(list), 0 );

	char delim[] = "\n";
	char string[MAX_SEND_SIZE] = {0};
	strcpy(string, list);

	// Account Balance 
	char* accountBalanceTemp = strtok(string, delim); 
	int accountBalance = atoi(accountBalanceTemp);

	// if(payMoney > accountBalance){
	// 	printf("\nPlease check your account balance, you cannot pay more money than that to others.\n");
	// 	return false;
	// }


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
			try
			{
				int socket_desc_p2p;
    			struct sockaddr_in otherClient;
				
				socket_desc_p2p = socket(AF_INET , SOCK_STREAM , 0);
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

				if (connect(socket_desc_p2p , (struct sockaddr *)&otherClient , sizeof(otherClient)) < 0)
				{
					cout << ("connect error, please retry.\n\n");
					cout << strerror(errno) << endl;
					return false;
				}

				else if( send(socket_desc_p2p , transMessage , strlen(transMessage) , 0) < 0)
				{
					cout << ("\n590Send failed\n Maybe server is still unconnected, please check your server is online,\n");
					return false;
				}

				else{
					printCyan();
					// printf("Transfer Ok\n\n");
					char buffer[MAX_BUFFER_SIZE] ={0};
					// Prototype of recv()
					ssize_t recv(int sockfd, void *buf, size_t len, int flags);
					recv(socket_desc, buffer, sizeof(buffer), 0 );
					printf("\n-----------------------------\n");
					printf("Display returns from server for demo:\n");
					printf("%s\n", buffer);
					printf("\n-----------------------------\n");
					printDefault();
				}
				
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
		printf("There is no account named ' %s ' online.\n", payeeName);
		printf("Please check your input\n\n");
		return false;
	}
	return true;
}