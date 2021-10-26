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
#include <netinet/in.h>

#include "sha512.h"

#ifndef DEBUG
#define sniffer_debug(...)
#else
#define sniffer_debug(...) (fprintf(stdout, __VA_ARGS__))
#endif

pthread_mutex_t file_write_lock;
pthread_mutex_t hash_table_lock;

struct sniffer_config{
    char *capture_interface;
    char *logdir;
    int time_delta;
    int num_threads;
	int buffer_size;
    int verbosity;
    float buffer_fraction;
    int mode;
    int c_port;
    long n_elements;  // Parameters for bloom filter
    double fp_rate;
};


#define sniffer_config_init() { (char *)"wlp3s0", (char *)"output/", 0, 1, 20, 0, 0.1, 0, 0, 100, 0.01}

struct packet_info {
    struct timespec ts;
    uint32_t caplen;
    uint32_t len; 
    u_short is_valid;
    u_short ip_version;
    struct in_addr ip_src, ip_dst;
    u_short protocol;
    u_short ip_ttl;
    u_short sport, dport;

    uint32_t seq, ack_seq;
    u_short doff;
    u_short res1, res2;
    u_short urg;
    u_short ack;
    u_short psh;
    u_short rst;
    u_short fin;
    u_short syn;

    int payload_size;
    int ip_len;
    unsigned char payload_ascii[512*8]; /*Not to be used during implementation */
    unsigned char payload_hash[2*(SHA512_DIGEST_LENGTH + 1)];
    // TODO use a union like data type for storing tcp and udp packet details
};

enum status{
    status_ok = 0,
    status_err = 1
};
#endif
