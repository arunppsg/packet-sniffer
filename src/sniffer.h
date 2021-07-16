/*
 * sniffer.h
 */

#ifndef SNIFFER_H
#define SNIFFER_H

#define SIZE_ETHERNET 14
#define IP_HEADER_LEN 20

#include <stdint.h>
#include <sys/types.h>
#include <time.h>
#include <linux/in.h>

#include "sha512.h"

#ifndef DEBUG
#define sniffer_debug(...)
#else
#define sniffer_debug(...) (fprintf(stdout, __VA_ARGS__))
#endif

pthread_mutex_t file_write_lock; 
struct sniffer_config{
    char *capture_interface;
    char *output_json_file;
    int num_threads;
    int verbosity;
    float buffer_fraction;
};


#define sniffer_config_init() { (char *)"wlp3s0", (char *)"output.json", 1, 0, 0.1 }

struct packet_info {
    struct timespec ts; //timestamp
    uint32_t caplen; //length of capture (the size of capture in frame)
    uint32_t len; //length of packet
    u_short is_valid;
    u_short ip_version;
    struct in_addr ip_src, ip_dst;
    u_short protocol;
    u_short ip_ttl;
    u_short sport, dport;
    int payload_size;
    int ip_len;
    unsigned char payload_ascii[512*8]; /*Not to be used during implementation */
    unsigned char *payload_hexa;
    unsigned char payload_hash[2*SHA512_DIGEST_LENGTH];
    // TODO use a union like data type for storing tcp and udp packet details
};

enum status{
    status_ok = 0,
    status_err = 1
};
#endif
