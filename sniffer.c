#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>

#define CAPTURESIZE 2048

void print_packet(u_char *count, const struct pcap_pkthdr *h, const u_char *bytes){
    int i, *counter = (int *)count;
    printf("---------------------------------------");
    printf("Packet Count: %d\n",++(*counter));
    printf("Received packet with leangth %d ...\n", h->len);
    printf("Received at %s\n", ctime((const time_t*) &h->ts.tv_sec));
    printf("Payload: ");
    for(i=0; i < h->len; i++){
        if(isprint(bytes[i])){
            printf("%c", bytes[i]);
        } else {
            printf(".");
        } if(i%32 == 0 && i!=0 || i == h->len-1){
            printf("\n");
        }
    }
    return;
}

int main(int argc, char *argv[]){
    char *device = NULL;
    int count = 0;
    char error[PCAP_ERRBUF_SIZE];
    pcap_t *desc;
    char filter_expression[] = "port 80";
    struct bpf_program fp;
    bpf_u_int32 ip;
    bpf_u_int32 netmask;

    if(argc > 1){
        device = argv[1];
    } else {
        printf("Usage: %s <interface> \n",argv[0]);
        exit(0);
    }
    if(pcap_lookupnet(device, &ip, &netmask, error) == -1){
        printf("Cannot acquire netmask for the device %s ...\n",device);
        exit(-1);
    }
    printf("Opening device %s for sniffing...\n",device);
    desc = pcap_open_live(device, CAPTURESIZE, 1, 1, error);
    if(desc == NULL){
        printf("%s\n", error);
        exit(-1);
    } else {
        printf("Listening on %s ...\n", device);
    }
    if(pcap_compile(desc, &fp, filter_expression, 0, netmask) == -1){
        printf("Cannot parse filter %s: %s ...\n", filter_expression, pcap_geterr(desc));
        exit(-2);
    }
    if(pcap_setfilter(desc, &fp) == -1){
        printf("Cannot set filter using pcap_setfilter() %s: %s\n", filter_expression, pcap_geterr(desc));
        exit(-2);
    }
    if(pcap_loop(desc, -1, print_packet, (u_char *)&count) == -1){
        printf("Error: %s", pcap_geterr(desc));
        exit(-1);
    }
    return 0;
}
