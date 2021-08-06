#include <stdio.h>
#include "sniffer.h"

#ifndef JSON_FILE_IO_H
#define JSON_FILE_IO_H

struct log_file {
	char dirname[256];
	char filename[300];
	unsigned long pkt_count;
	int mode;
};

int write_packet_info(struct packet_info *, struct log_file *,
        pthread_mutex_t *);

#endif
