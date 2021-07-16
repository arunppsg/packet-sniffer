 /*
  * pkt_processing.c
  *
  * Extract's packet properties from raw payload.
  */

#include <stdio.h>
#include <pcap.h>
#include <openssl/sha.h>
#include <stdlib.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include "sniffer.h"
#include "sha512.h"
#include "pkt_processing.h"

void ascii_hex_dump(const char *payload, int payload_size,
         unsigned char *ascii_dump, unsigned char *hexa_dump){
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
 //   sniffer_debug("ASCII payload is %s\n", ascii_dump);
    // Byte 34 - ", 92 - \. These should be escaped in json but 
    // instead as a quick fix, we replace it by '.'
    /* If the below loop statement is placed inside above loop, it returns an 
     * empty string. Not sure why it happens.
     * Also it raises segmentation fault in some cases.
     * Again, not sure why it is happening and hence it is left unused.
     * TODO resolve using gdb

    for(i=0; i<payload_size; i++){
        byte = payload[i];
        sprintf(hexa_dump + i*2, "%02x", byte);
    }*/
    sniffer_debug("Got payload ascii\n");
}

void extract_tcp_packet(uint8_t *eth, u_short iphdr_len,
         struct packet_info *pi){
    /*
     * Reference docs: https://datatracker.ietf.org/doc/html/rfc793 
     */
    sniffer_debug("Extracting TCP packet.. "); 
    struct tcphdr *tcph = (struct tcphdr *)(eth + ETH_HLEN + iphdr_len);
    const char *payload;
    int tcphdr_len = (unsigned int)tcph->doff * 4;
    if(tcphdr_len < 20){  // Invalid TCP Header. Min. size of tcp header = 5 words = 20 bytes
        return;
    }
    pi->sport = ntohs(tcph->source);
    pi->dport = ntohs(tcph->dest);
    
    payload = (const char *)(eth + SIZE_ETHERNET + iphdr_len + tcphdr_len);
    int payload_size = pi->ip_len - (iphdr_len + tcphdr_len);
    if(payload_size > 0){
        sha512(payload, pi->payload_hash);
        pi->is_valid = 1;
        pi->payload_size = payload_size; 
        ascii_hex_dump(payload, payload_size,
                pi->payload_ascii, pi->payload_hexa); 
   } 
   sniffer_debug("Extracted tcp\n");
   return;
}


void extract_udp_packet(uint8_t *eth, u_short iphdr_len,
        struct packet_info *pi){
    /*
     * Reference docs: https://datatracker.ietf.org/doc/html/rfc768
     */
    sniffer_debug("Extracting UDP packet..  ");
    struct udphdr *udph = (struct udphdr *)(eth + ETH_HLEN + iphdr_len);
    const char *payload;
    payload = (const char *)(eth + SIZE_ETHERNET + iphdr_len + UDP_HEADER_LEN);
    int payload_size = ntohs(udph->len) - UDP_HEADER_LEN;
    if(payload_size > UDP_HEADER_LEN){
        sha512(payload, pi->payload_hash);
        pi->is_valid = 1;
        pi->payload_size = payload_size; 
        ascii_hex_dump(payload, payload_size,
                pi->payload_ascii, pi->payload_hexa); 
    }
    sniffer_debug("Extracted\n"); 
    return;
}

int extract_packet_info(uint8_t *eth, struct packet_info *pi){
    /*
     * Reference docs: https://datatracker.ietf.org/doc/html/rfc791
     */
    sniffer_debug("Extracting IP packet.. ");
    pi->is_valid = 0;
    struct iphdr *iph = (struct iphdr *)(eth + ETH_HLEN);
//    if(eth->h_proto == htons(ETH_P_IP)){ TODO Is this check needed?
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
            switch(pi->protocol){
                case IPPROTO_TCP:
                    extract_tcp_packet(eth, iphdr_len, pi);
                    break;
                case IPPROTO_UDP:
                    extract_udp_packet(eth, iphdr_len, pi);
                    break;
            }
        } else {  // Not collecting IPv6
            pi->is_valid = 0;
        }
/*    } else {  // Not an IP packet
        pi->is_valid = 0;
    }*/
    sniffer_debug("Extracted IP packet\n");
    return 0;
}
