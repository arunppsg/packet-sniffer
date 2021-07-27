#include <stdio.h>
#include <string.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#ifndef TCP_FLOOD_H
#define TCP_FLOOD_H

#ifndef DEBUG
#define debug(...)
#else
#define debug(...) (fprintf(stdout, __VA_ARGS__))
#endif

struct test_config {
    int timeout_time;
    int thread_count;
    char *dest_ip;
    int rate;  // Number of packets to send per second
};

#define test_config_init() {10, 1, (char*)"192.168.1.1", 100}

#endif
