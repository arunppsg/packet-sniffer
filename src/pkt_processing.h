 /*
 * Header file for extracting payload.  
 */
#ifndef PKT_PROCESSING_H
#define PKT_PROCESSING_H

#define SIZE_ETHERNET 14
#define IP_HEADER_LEN 20 
#define UDP_HEADER_LEN 8

int extract_packet_info(uint8_t *eth, struct packet_info *pi);

#endif
