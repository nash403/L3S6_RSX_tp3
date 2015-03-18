/* Auteur : Honoré NINTUNZE
 * TP3 Question 2*/

#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>

int main(int argc, char **argv) {
	struct sockaddr_in dest;
	char* msg = argv[1];
	int sk = socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);

	dest.sin_family = AF_INET;
	dest.sin_addr.s_addr = inet_addr("172.18.12.202");//127.0.0.1
	dest.sin_port = htons(15000);

	sendto(sk, msg, strlen(msg),0,(struct sockaddr*) &dest,sizeof(dest));

	printf("chaine envoyée : %s\n", msg);

	return 0;


}
