#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h> //IPv4 and IPv6
#include <arpa/inet.h>

int main(int argc, char *argv[]) {
	char error[PCAP_ERRBUF_SIZE];
	pcap_if_t *interfaces, *temp;
	int i =0;
	
	if(pcap_findalldevs(&interfaces, error) == -1){
		printf("[!] Cannot acquire the devices \n");
		return -1;
	}
	printf("The available devices are: \n");
	for (temp=interfaces; temp; temp=temp->next){
		printf("#%d : %s\n", ++i,temp->name);
	}
	return 0;
}
