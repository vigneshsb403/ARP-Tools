#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h> //IPv4 and IPv6
#include <arpa/inet.h>
#include <time.h>
#include <netinet/if_ether.h>
#include <unistd.h>

#define ARP_REQUEST 1
#define ARF_RESPONSE 2
int isilent;
int isnonoti;
typedef struct _arp_hdr arp_hdr;
struct _arp_hdr {
	uint16_t htype;
	uint16_t ptype;
	uint8_t hlen;
	uint8_t plen;
	uint16_t opcode;
	uint8_t sender_mac[6];
	uint8_t sender_ip[4];
	uint8_t target_mac[6];
	uint8_t target_ip[4];
};

int print_available_interfaces(){
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

int print_help(char *bin){
	printf("Available Arguments: \n");
	printf("--------------------\n");
	printf("[-h][--help]\t\t : Prints this and exits.\n");
	printf("[-l][--lookup]\t\t : Displays the available interfaces.\n");
	printf("[-v][--version]\t\t : Displays the current version.\n");
	printf("[-i][--interface]\t : Provide the interface to sniff on.\n");
	printf("[-q][--silent]\t\t : Run the tool without information.\n");
	printf("[-n][--no-notification]\t : Run the tool without notifications.\n");
	printf("-----------------------------------------------\n");
	printf("Usage: %s -i interface \n",bin);
	return -1;
}

void print_greeting(){
	printf("     ___    ____  ____ 		\n");
	printf("    /   |  / __ \\/ __ \\	\n");
	printf("   / /| | / /_/ / /_/ /		\n");
	printf("  / ___ |/ _, _/ ____/ 		\n");
	printf(" /_/  |_/_/ |_/_/   Spoof Detector v1.2\n");
	printf("			   By. vigneshsb403\n\n");
}

int print_version(){
	printf("Arp Spoof Detector v1.0 \n");
	return -1;
}

char* get_hardware_address(uint8_t mac[6]){
	char *gmac = (char*)malloc(20*sizeof(char));
	sprintf(gmac, "%02X:%02X:%02X:%02X:%02X:%02X",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
	printf("\n");
	return gmac;
}
char* get_ip_address(uint8_t ip[4]){
	char *gip = (char*)malloc(20*sizeof(char));
	sprintf(gip,"%d.%d.%d.%d",ip[0],ip[1],ip[2],ip[3]);
	return gip;
}
int spoof_alert(char *ip, char *mac){
	FILE *output=popen("awk -F':' -v uid=1000 '$3 == uid { print $1 }' /etc/passwd","r");
	char notif[512];
	char buffer1[100];
	fgets(buffer1, 100, output);
	char *buffer;
	buffer=buffer1;
	char *beta;
	int size=0;
	int counter=0;
	while(1){
		if(buffer[counter]!='\n'){
			counter++;
			size++;
		}else{
			break;
		}
	}
	beta = (char *)malloc(sizeof(char)*size);
	for(int i=0;i<size;i++){
		beta[i]=buffer[i];}
	sprintf(notif,"sudo -u %s DISPLAY=:0 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus notify-send 'ARP Spoof Detected!' 'Spoofing from IP: %s MAC:%s'",beta,ip,mac);
	system(notif);
	return 0;
}
int print_info(char *s_mac,char *s_ip,char *t_mac, char *t_ip){
	printf("Sender MAC : %s\n", s_mac);
	printf("Sender IP: %s\n", s_ip);
	printf("Target MAC: %s\n", t_mac);
	printf("Target IP: %s\n", t_ip);
	printf("----------------------------------------------------");
	return 0;
}
int sniff_arp(char *device_name){
	char error[PCAP_ERRBUF_SIZE];
	pcap_t* pack_desc;
	const u_char *packet;
	struct pcap_pkthdr header;
	struct ether_header *eptr;
	arp_hdr *arpheader = NULL;
	u_char *hard_ptr;
	int i;
	char *s_mac,*s_ip,*t_mac,*t_ip;
	int counter=0;
	time_t crtime,ltime;
	long int diff=0;
	
	pack_desc = pcap_open_live(device_name, BUFSIZ, 0, 1, error);
	if(pack_desc == NULL){
		printf("[!] %s\n",error);
		print_available_interfaces();
		return -1;
	} else {
		printf("[INFO]Sniffing on %s...\n",device_name);
	}
	while(1){
		packet = pcap_next(pack_desc, &header);
		if(packet == NULL){
			printf("[!]Cannot capture packet\n");
			return -1;
		} else{
			eptr = (struct ether_header*) packet;
			if(ntohs(eptr->ether_type) == ETHERTYPE_ARP){
				crtime=time(NULL);
				arpheader=(arp_hdr*)(packet+14);
				if(isnonoti==0){
					printf("\nReceived a ARP packet with length %d\n",header.len);
					printf("Received at %s", ctime((const time_t*) &header.ts.tv_sec));
					printf("Ethernet Header Length: %d\n",ETHER_ADDR_LEN);
					printf("Operation type: %s\n",(ntohs(arpheader->opcode) == ARP_REQUEST ? "ARP Request ": "APR Responce"));
				} else{
					printf("[INFO]Sniffing on %s...",device_name);
				}
				s_mac= get_hardware_address(arpheader->sender_mac);
				s_ip= get_ip_address(arpheader->sender_ip);
				t_mac = get_hardware_address(arpheader->target_mac);
				t_ip = get_ip_address(arpheader->target_ip);
				if(isnonoti==0){
					print_info(s_mac, s_ip, t_mac, t_ip);
				}
				counter++;
				ltime=time(NULL);
				diff=ltime-crtime;
				if(diff>20){
					counter=0;
				}
				if(counter>10){
					printf("[CRITICAL]: ARP Spoofing Detected. IP: %s MAC: %s\n",s_mac,s_ip);
					if(counter%5==0){
						if(isilent==0){
							spoof_alert(s_ip, s_mac);
						} else{
							;
						}
					}else{
						continue;
					}
				}
			}
		}
	}	return 0;
}
int welcome_note(){
	FILE *output=popen("awk -F':' -v uid=1000 '$3 == uid { print $1 }' /etc/passwd","r");
	char notif[512];
	char buffer1[100];
	fgets(buffer1, 100, output);
	char *buffer;
	buffer=buffer1;
	char *beta;
	int size=0;
	int counter=0;
	while(1){
		if(buffer[counter]!='\n'){
			counter++;
			size++;
		}else{
			break;
		}
	}
	beta = (char *)malloc(sizeof(char)*size);
	for(int i=0;i<size;i++){
		beta[i]=buffer[i];}
	sprintf(notif,"sudo -u %s DISPLAY=:0 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus notify-send 'Hello, World!' 'ARP Spoof detector is running sit back and relax'",beta);
	system(notif);
	return 0;
}
int main(int argc, char *argv[]) {
	print_greeting();
	if(access("/usr/bin/notify-send", F_OK) == -1){
		printf("[!] Missing Dependency: notify-send\n");
		printf("[!]install the same using: sudo apt-get install libnotify-bin\n");
		exit(-1);
	}
	isilent=0;
	isnonoti=0;
	int i;
	
	if(argc<2){
		print_help(argv[0]);
		exit(-1);
	}
	for(i=0;i<argc;i++){
		if(strcmp(argv[i],"-q")==0 || strcmp(argv[i],"--silent")==0){
			isilent=1;
		}
		if(strcmp(argv[i],"-n")==0 || strcmp(argv[1],"--no-notification")==0){
			isnonoti=1;
		}
	}
	if(strcmp(argv[1],"-h")==0 || strcmp(argv[1],"--help")==0){
		print_help(argv[0]);
		exit(-1);
	} else if(strcmp(argv[1],"-v")==0 || strcmp(argv[1],"--version")==0){
		print_version();
		exit(-1);
	} else if(strcmp(argv[1],"-l")==0 || strcmp(argv[1],"--lookup")==0){
		print_available_interfaces();
		exit(-1);
	} else if((strcmp(argv[1],"-i")==0 || strcmp(argv[1],"--interface")==0)){
		if(argc<3){
			printf("[!]ERROR: Interface missing after -i argument.\n\n");
			print_available_interfaces();
			exit(-1);
		} else{
			if(isnonoti==0){
			if(access("/usr/bin/notify-send", F_OK) == -1){
		printf("[!] Missing Dependency: notify-send\n");
		printf("[!]install the same using: sudo apt-get install libnotify-bin\n");
		printf("[INFO]Use -n argument to avoid this error.\n");
		exit(-1);
	}
			welcome_note();
			}
			sniff_arp(argv[2]);
		}
	} else {
		printf("Usage: %s -i interface \n",argv[0]);
		exit(-1);
	}
	
}
