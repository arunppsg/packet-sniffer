#include <stdio.h>
#include <pthread.h>
#include <pcap/pcap.h>
#include <openssl/sha.h>
#include <string.h>
#include <time.h>
#include <netinet/in.h>

#include "json_file_io.h"
#include "sniffer.h"
#include "bloom_filter.h"

#define MAX_JSON_STRING_SIZE 65536
#define MAX_FIELD_SIZE 65536
#define ENTRIES_PER_LOG 10000000
#define MAX_FILENAME_SIZE 100

static long int packet_count = 0;
static char filename[MAX_FILENAME_SIZE] = "";

int write_json(const char *json, char *output_file_name){
    /*
     * Refer: https://stackoverflow.com/questions/12451431/loading-and-parsing-a-json-file-with-multiple-json-objects
     * https://datatracker.ietf.org/doc/html/rfc7159
     */
    if(packet_count == 0){
        time_t rawtime;
        time(&rawtime);
        sprintf(filename, "%s%ld.json", output_file_name, rawtime);
    }    
    packet_count = (packet_count + 1) % ENTRIES_PER_LOG;
    
    // create file if it doesn't exist
    FILE* fp = fopen(filename, "r"); 
    if (!fp)
    {
       fp = fopen(filename, "w"); 
    } 
    fclose(fp);
    
    // add the document to the file
    fp = fopen(filename, "a");
    if (fp)
    {
        // append the document
        fputs(json, fp);
        fputs("\n", fp);     
    }
    fclose(fp);

    return 0;
}


int write_packet_info(struct packet_info *pi, char *output_file_name){
     
    char json[MAX_JSON_STRING_SIZE] = "";
    char text[MAX_FIELD_SIZE] = "";

    sniffer_debug("Extracting packet details in write_packet_info \n");
    sprintf(text, "{\"timestamp\":%lld.%.9ld,", (long long)pi->ts.tv_sec, pi->ts.tv_nsec);
    strcpy(json, text);

    sprintf(text, "\"s_ip\":\"%s\",", inet_ntoa(pi->ip_src));
    strcat(json, text);

    sprintf(text, "\"d_ip\":\"%s\",", inet_ntoa(pi->ip_dst));
    strcat(json, text);

    sprintf(text, "\"ip_version\":%d,", pi->ip_version);
    strcat(json, text);

    sprintf(text, "\"protocol\":%d,", pi->protocol);
    strcat(json, text);
    
    sprintf(text, "\"s_port\":%d, \"d_port\":%d,", 
            pi->sport, pi->dport);
    strcat(json, text);
    
    if(pi->protocol == IPPROTO_TCP){
        sprintf(text, "\"seq\":%d, \"ack_seq\":%d,",
                pi->seq, pi->ack_seq);
        strcat(json, text);

        sprintf(text, "\"doff\":%d, \"res1\":%d,",
                pi->doff, pi->res1);
        strcat(json, text);

        sprintf(text, "\"res2\":%d, \"urg\":%d,",
            pi->res2, pi->urg);
        strcat(json, text);

        sprintf(text, "\"ack\":%d, \"psh\":%d,",
            pi->ack, pi->psh);
        strcat(json, text);

        sprintf(text, "\"syn\":%d, \"rst\":%d, \"fin\":%d,",
                pi->syn, pi->rst, pi->fin);

    }

    sprintf(text, "\"payload_size\":%d,", pi->payload_size);
    strcat(json, text);

//    sprintf(text, "\"payload_ascii\":\"%s\",", pi->payload_ascii);
//    strcat(json, text);

    sprintf(text, "\"payload_hash\":\"%s\"}", pi->payload_hash);
    strcat(json, text);

//    printf("%s\n", json);
    pthread_mutex_lock(&file_write_lock);  
    write_json(json, output_file_name);
    pthread_mutex_unlock(&file_write_lock);
    sniffer_debug("Extracted packet details in write_packet_info \n");    
    return 0;         
}

