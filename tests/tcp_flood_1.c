#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>
#include <pthread.h>
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
    "   [-r or --rate] rate at which to generate packets \n"
    "Others:\n"
    "   Destionation port: 80\n"
    "   Protocol: TCP\n";

struct thread_storage {
    int tnum;
    pthread_t tid;
    int sockfd;
    double delay;
    const char *dest_ip;
    char *datagram;
};

void *flood(void *);

void *flood(void *tstor_arg){
    struct thread_storage *tstor = (struct thread_storage *) tstor_arg;
    int sockfd = tstor->sockfd;
    char *datagram = tstor->datagram;
    double delay = tstor->delay;
    int err;
    while(1){
       err = send(sockfd, datagram, 1024, 0); 
       if(err < 0)
           printf("Send failed %d error message %s in thread %d\n", 
                   err, strerror(err), tstor->tnum);
       else
           printf("Successfuly sent packet in thread %d\n", tstor->tnum);
       fflush(stdout);
       sleep(delay);
    }
}

int generate_packet(char* datagram, struct test_config *cfg){

    //struct ether_header *eh; ethernet header is added by OS 
    //eh = (struct ether_header *) datagram;
    //construct_ethernet_header(eh);
    struct iphdr *iph;
    struct tcphdr *tcph;
    char *payload;

    iph = (struct iphdr *) (datagram);
    construct_ip_header(iph, cfg->dest_ip);
    print_ip_header(iph);

    tcph = (struct tcphdr *)(datagram + sizeof(struct iphdr));
    construct_tcp_header(tcph);

    payload = (char *)(datagram + sizeof(struct iphdr) + sizeof(struct tcphdr));
    construct_payload(payload);
    
    return 0;
}

int main(int argc, char *argv[]){
    struct test_config cfg = test_config_init();

    int c;
    while(1){
        enum opt {dest_ip = 1, threads = 2, 
                    help = 3};
        int option_index = 0;
        static struct option long_options[] = {
            {"dest_ip", optional_argument, 0, 'd'},
            {"threads", optional_argument, 0, 'T'},
            {"help", no_argument, 0, 'h'},
            {"rate", optional_argument, 0, 'r'}
        };

        c = getopt_long(argc, argv, "d:t:T:r:h",
                long_options, &option_index);

        if(c == -1)
            break;

        switch(c){
            case 'd':
                cfg.dest_ip = optarg; 
                break;
            case 't':
                cfg.timeout_time = strtol(optarg, NULL, 10);
                break;
            case 'T':
                cfg.thread_count = strtol(optarg, NULL, 10);
                break;
            case 'r':
                cfg.rate = strtol(optarg, NULL, 10);
                break;
            default:
                printf("%s\n", tcp_generator_help);
                exit(0);
                break;
        }
    }

    char datagram[4096];
    memset(datagram, 0, 4096);

    generate_packet(datagram, &cfg);

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(80);
    sin.sin_addr.s_addr = inet_addr(cfg.dest_ip); // destination address

    int err;
    struct thread_storage tstor;
    tstor.tnum = 0;
    tstor.delay = 1 / cfg.rate; 
    tstor.dest_ip = cfg.dest_ip;
    tstor.datagram = datagram;

    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if(sockfd == -1){
        fprintf(stderr, "error creating socket for thread \n"); 
        exit(255);
    }
    tstor.sockfd = sockfd;
    int thread = 0;
    int val = 1;
    err = setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &val, sizeof(val));
    if(err){
        fprintf(stderr, "error setting socket options for thread \n");
        exit(255);
    }

    err = connect(sockfd, (struct sockaddr *)&sin, sizeof(sin));
    if(err != 0)
        printf("connection failed %d error message %s for thread %d\n", 
                err, strerror(err), thread);
    else
        printf("Successfully connected for thread %d\n", thread);

    tstor.datagram = datagram;

    pthread_attr_t thread_attributes;
    err = pthread_attr_init(&thread_attributes); 
    if(err != 0){
        fprintf(stderr, "%s: error initializing thread attributes for thread %d\n", 
                strerror(err), thread);
        exit(255);
    }

    err = pthread_create(&(tstor.tid), &thread_attributes,
            flood, &(tstor));
    if(err){
       fprintf(stderr, "error creating thread %d\n", thread);
       exit(255);
    }

    pthread_join(tstor.tid, NULL); 
    return 0;
}
