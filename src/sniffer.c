/*
 * sniffer.c - main
 */

#include <stdio.h>
#include <pcap.h>
#include <openssl/sha.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/sysinfo.h>
#include <getopt.h>
#include <sys/sysinfo.h>
#include <stdlib.h>
#include <errno.h>

#include "sniffer.h"
#include "af_packet_v3.h"
#include "signal_handling.h"

char sniffer_help[] = "TODO";

int main(int argc, char *argv[]){

    struct sniffer_config cfg = sniffer_config_init(); 
    int c;
    while(1){
        enum opt {capture_interface=1, json_file=2,
            thread_count=3, verbosity=4,
            help=5 };
        int option_index = 0;
        static struct option long_options[] = {
            {"capture_interface", optional_argument, 0, 'c'},
            {"json_file", optional_argument, 0, 'j'},
            {"thread_count", optional_argument, 0, 't'},
            {"help", no_argument, 0, 'h'},
            {"verbosity", no_argument, 0, 'v'}
        };
        c = getopt_long(argc, argv, "c:j:t:h:v",
                long_options, &option_index);

        if(c == -1)  /* end of options */
            break;

        switch(c){
            case 'c': 
                cfg.capture_interface = optarg;
                sniffer_debug("Capture interface is %s\n", cfg.capture_interface);
                break;
            case 'j':
                cfg.output_json_file = optarg;
                sniffer_debug("Output file name %s\n", cfg.output_json_file);
                break;
            case 't':
                cfg.num_threads = strtol(optarg, NULL, 10);
                break;
            case 'v':
                cfg.verbosity = 1;
                break;
            case 'h':
                printf("%s\n", sniffer_help);
                break;
            default:
                printf("Invalid configuration list\n");
                exit(0);
        }
    }
   
    if(setup_signal_handler() != status_ok){
       fprintf(stderr, "%s: error in setting up signal handlers\n", strerror(errno));
    }

    sniffer_debug("Initialized configuration file\n");
    int status;
    status = bind_and_dispatch(&cfg);
    sniffer_debug("Status %d\n", status);
  
    return 0;
}


