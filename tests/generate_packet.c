#include <stdio.h>
#include <string.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "tcp_flood.h"

int construct_ethernet_header(struct ether_header *eh){
    memcpy(eh->ether_shost, "buddy", 6);  /* Some source host name */
    memcpy(eh->ether_dhost, "ponni", 6);  /* Some destination host name */
    eh->ether_type = htons(ETH_P_IP);
    return 0;
}

int print_ethernet_header(struct ether_header *eh){
    debug("Source host: %s \nDestination host %s\n", eh->ether_shost,
            eh->ether_dhost);
    return 0;
}

int construct_ip_header(struct iphdr *iph, char *dest_ip){
   iph->ihl = 5;
   iph->version = 4;
   iph->tos = 16;
   iph->id = htons(54321);
   iph->protocol = 6; // tcp
   iph->saddr = inet_addr("13.13.13.13");
   iph->daddr = inet_addr(dest_ip);
   return 0;
}

int print_ip_header(struct iphdr *iph){
    struct in_addr in, out;
    in.s_addr = iph->saddr;
    out.s_addr = iph->daddr;
    debug("IP header length %d" \
          " IP version %d" \
          " protocol  %d" \
          "\nSource address %s " \
          "Destination address %s\n",
          iph->ihl, iph->version, iph->protocol,
          inet_ntoa(in), inet_ntoa(out));
    return 0;
}

int construct_tcp_header(struct tcphdr *tcph){
    tcph->source = htons(13);
    tcph->dest = htons(80);
    tcph->seq = 0;
    tcph->ack_seq = 2;
    tcph->doff = 5;
    return 0;
}

int print_tcp_header(struct tcphdr *tcph){
    debug("TCP Header length %d " \
          "TCP source port %d " \
          "TCP destination port %d \n", 
          tcph->doff, ntohs(tcph->source), ntohs(tcph->dest));
    return 0;
}

int construct_payload(char *payload){
   memcpy(payload, "Hello Target!", 15);
   return 0;
}

int print_payload(char *payload){
    debug("Payload is %s\n", payload);
    return 0;
}

