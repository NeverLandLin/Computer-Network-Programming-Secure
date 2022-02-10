#ifndef _UTILITY
#define _UTILITY

void printRed(){
	printf("\033[0;31m");
}

void printYellow(){
	printf( "\033[0;33m");
}

void printCyan(){
	printf("\033[1;36m");
}

void printLightGreen(){
	printf("\033[1;32m");
}

void printBlack(){
	printf("\033[0;30m");
}


void printDefault(){
	printf( "\033[0m");	
}



#endif