#include <bits/stdc++.h>
using namespace std;

int main () {
	string a = "openssl req -x509 -new -nodes -sha256 -utf8 -days 3650 -newkey rsa:2048 -keyout server.key -out server.crt -config ssl.conf";
	system(a.c_str());
	return 0;
}
