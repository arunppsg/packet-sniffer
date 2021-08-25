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

#include "include/sniffer.h"
#include "include/af_packet_v3.h"
#include "include/signal_handling.h"

char sniffer_help[] = " \
Example Usage: \n\
    For capturing in interface eno1: \n\
        ./sniffer -c eno1 \n\
    For using 2 threads: \n\
        ./sniffer -T 2 \n\
    For capturing upto 10 seconds: \n\
        ./sniffer -t 10 \n\
	For choosing buffer fraction: \n\
		./sniffer -f 0.05 \n\
    For choosing output directory (file path should be complete path): \n\
        ./sniffer -d /Users/Alice/ \n\
    For choosing capture mode: \n\
        Mode can be 0, 1 or 2. 0 generates only log files \n\
        1 builds bloom filter. 2 applies the built bloom filter \n\
        ./sniffer -m 0 \n\
    For help: \n\
        ./sniffer --help \n\
";


int main(int argc, char *argv[]){

    struct sniffer_config cfg = sniffer_config_init(); 
    int c;
    while(1){
        enum opt {capture_interface=1, dir_name=2,
            time=3, thread_count=4, mode=5, buffer_fraction=7,
            verbosity=6, help=5, port_number=8 };
        int option_index = 0;
        static struct option long_options[] = {
            {"capture_interface", optional_argument, 0, 'c'},
            {"dir_name", optional_argument, 0, 'd'},
            {"time", optional_argument, 0, 't'},
            {"thread_count", optional_argument, 0, 'T'},
			{"buffer_fraction", optional_argument, 0, 'b'},
            {"mode", optional_argument, 0, 'm'},
            {"help", no_argument, 0, 'h'},
            {"verbosity", no_argument, 0, 'v'},
            {"port_number", no_argument, 0, 'p'},
            {"n", no_argument, 0, 'n'},
            {"error_rate", no_argument, 0, 'e'}
        };
        c = getopt_long(argc, argv, "c:d:T:t:m:b:h:v:p:n:e:",
                long_options, &option_index);

        if(c == -1)  /* end of options */
            break;

        switch(c){
            case 'c': 
                cfg.capture_interface = optarg;
                sniffer_debug("Capture interface is %s\n", cfg.capture_interface);
                break;
            case 'd':
                cfg.logdir = optarg;
                sniffer_debug("Log directory %s\n", cfg.logdir);
                break;
            case 't':
                cfg.time_delta = strtol(optarg, NULL, 10);
                break;
            case 'T':
                cfg.num_threads = strtol(optarg, NULL, 10);
                break;
			case 'b':
				cfg.buffer_fraction = strtof(optarg, NULL);
				break;
            case 'v':
                cfg.verbosity = 1;
                break;
            case 'm':
                cfg.mode = strtol(optarg, NULL, 10);
                break;
            case 'p':
                cfg.c_port = strtol(optarg, NULL, 10);
                break;
            case 'h':
                printf("%s\n", sniffer_help);
                exit(0);
                break;
            case 'e':
                cfg.fp_rate = strtof(optarg, NULL);
                break;
            case 'n':
                cfg.n_elements = strtol(optarg, NULL, 10);
                break;
            default:
                printf("%s\n", sniffer_help);
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
