 /*
  * pkt_processing.c
  *
  * Extract's packet properties from raw payload.
  */

#include <stdio.h>
#include <pcap.h>
#include <openssl/sha.h>
#include <stdlib.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "sniffer.h"
#include "sha512.h"
#include "pkt_processing.h"

void ascii_hex_dump(const char *payload, int payload_size,
         unsigned char *ascii_dump){
    sniffer_debug("Getting ascii of payload..  ");
    unsigned char byte;
    int i;
    for(i=0; i<payload_size; i++){
        byte = payload[i];
        if((byte > 31) && (byte < 123) //Byte in printable character range
                && (byte != 34) && (byte != 92))
            sprintf((char*)ascii_dump+i, "%c", byte);
        else
            sprintf((char*)ascii_dump+i, ".");
        if(i == 4096) //Records only the first 512 bytes
            break;
    }
    
    sniffer_debug("Got payload ascii\n");
}

char* parse_tcp_packet(uint8_t *eth, u_short iphdr_len,
         struct packet_info *pi){
    /*
     * Reference docs: https://datatracker.ietf.org/doc/html/rfc793 
     */
    sniffer_debug("Extracting TCP packet.. "); 
    struct tcphdr *tcph = (struct tcphdr *)(eth + ETH_HLEN + iphdr_len);
    int tcphdr_len = (unsigned int)tcph->doff * 4;
    if(tcphdr_len < 20){  // Invalid TCP Header. Min. size of tcp header = 5 words = 20 bytes
        return NULL;
    }
    pi->sport = ntohs(tcph->source);
    pi->dport = ntohs(tcph->dest);

    pi->seq = ntohs(tcph->seq);
    pi->ack_seq = ntohs(tcph->ack_seq);
    pi->doff = tcph->doff;
    pi->res1 = tcph->res1;
    pi->res2 = tcph->res2;
    pi->urg = tcph->urg;
    pi->ack = tcph->ack;
    pi->psh = tcph->psh;
    pi->syn = tcph->syn;
    pi->rst = tcph->rst;
    pi->fin = tcph->fin;
    
    char *payload = (char *)(eth + SIZE_ETHERNET + iphdr_len + tcphdr_len);
    sniffer_debug("Extracted tcp\n");
    return payload;
}


char* parse_udp_packet(uint8_t *eth, u_short iphdr_len,
        struct packet_info *pi){
    /*
     * Reference docs: https://datatracker.ietf.org/doc/html/rfc768
     */
    sniffer_debug("Extracting UDP packet..  ");
    struct udphdr *udph = (struct udphdr *)(eth + ETH_HLEN + iphdr_len);
    pi->sport = ntohs(udph->source);
    pi->dport = ntohs(udph->dest);
    char *payload = (char *)(eth + SIZE_ETHERNET + iphdr_len + UDP_HEADER_LEN);
    sniffer_debug("Extracted\n"); 
    return payload;
}

int parse_packet(uint8_t *eth, struct packet_info *pi){
    /*
     * Reference docs: https://datatracker.ietf.org/doc/html/rfc791
     */
    sniffer_debug("Extracting IP packet.. ");
    pi->is_valid = 0;
    struct iphdr *iph = (struct iphdr *)(eth + ETH_HLEN);
        /* We determine IP protocol. IPv4 and IPv6 has different header structures */
        if(iph->version == 4){
            u_short iphdr_len = iph->ihl * 4; // ip->iphl contains the header len in words. 1 word = 4 octet.
            if(iphdr_len < IP_HEADER_LEN) {
                pi->is_valid = 0;
                return 0;
            }
            pi->ip_version = 4;
            pi->protocol = iph->protocol; // TCP or UDP
            pi->ip_src.s_addr = iph->saddr;
            pi->ip_dst.s_addr = iph->daddr;
            pi->ip_ttl = iph->ttl;
            pi->ip_len = ntohs(iph->tot_len);
//            pi->identification = ntohs(iph->id);
            sniffer_debug("Extracted IP info\n");
            char *payload;
            switch(pi->protocol){
                case IPPROTO_TCP:
                    payload = parse_tcp_packet(eth, iphdr_len, pi);
                    break;
                case IPPROTO_UDP:
                    payload = parse_udp_packet(eth, iphdr_len, pi);
                    break;
                default:
                    pi->is_valid = 0;
                    return 0;
            }
            if(!payload)
               return 0; 
            int payload_size = strlen(payload);
            if(payload_size > 3){
                strcpy((char *)pi->payload_hash, "");
                sha512(payload, pi->payload_hash);
                pi->is_valid = 1;
                pi->payload_size = payload_size; 
                ascii_hex_dump(payload, payload_size,
                        pi->payload_ascii); 
            }

        } else {  // Not collecting IPv6
            pi->is_valid = 0;
        }
    sniffer_debug("Extracted IP packet\n");
    return 0;
}
