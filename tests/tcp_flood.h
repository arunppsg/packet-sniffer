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

#endif
