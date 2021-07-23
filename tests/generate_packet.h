#include <stdio.h>
#include <string.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "tcp_flood.h"

#ifndef GENERATE_PACKET_H
#define GENERATE_PACKET_H

int construct_ethernet_header(struct ether_header *);
int construct_ip_header(struct iphdr *, char*);
int construct_tcp_header(struct tcphdr *);
int construct_payload(char *);

int print_ethernet_header(struct ether_header *);
int print_ip_header(struct iphdr *);
int print_tcp_header(struct tcphdr *);
int print_payload(char *);

#endif

