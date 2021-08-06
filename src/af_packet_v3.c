/*
 * af_packet_v3.c
 *
 * interface to AF_PACKET/TPACKETv3 with RXRING and FANOUT
 *
 * This software is derived from Cisco Mercury.
 * Reference: https://github.com/cisco/mercury
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>
#include <time.h>
#include <math.h>
#include <sched.h>
#include <sys/mman.h>
#include <poll.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/sysinfo.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

#include "signal_handling.h"
#include "sniffer.h"
#include "pkt_processing.h"
#include "json_file_io.h"
#include "utils.h"
#include "bloom_filter.h"

/* 
 * Signal Handling
 *
 * We need the stats tracking thread to end before we stop processing
 * packets or else we run the risk of exiting packets processing loops
 * and then later measuring false drops on those sockets at the end.
 * To that end, stats tracking will watch sig_close_flag and packet
 * worker threads will watch sig_close_workers.
 */
extern int sig_close_flag; /*Defined in signal_handling.c */
static int sig_close_workers = 0;

static double time_elapsed(struct timespec *ts){
    double time_s;
    time_s = ts->tv_sec + (ts->tv_nsec / 1000000000.0);
    
    if(clock_gettime(CLOCK_REALTIME, ts) != 0){
        perror("Unable to get clock time for elapsed calcualation");
        return NAN;
    }

    return (ts->tv_sec + (ts->tv_nsec / 1000000000.0)) - time_s;
}


/* The ring_limits struct describe the memory allocation and other
 * properties of ring */
struct ring_limits {
    uint64_t af_desired_memory;
    uint64_t af_ring_limit;
    uint64_t af_framesize;
    uint64_t af_blocksize;
    uint64_t af_min_blocksize;
    uint64_t af_target_blocks;
    uint64_t af_min_blocks;
    uint32_t af_blocktimeout;
    uint32_t af_fanout_type;
};

/* struct stats_tracking tracks stats for each thread and stores 
 * those stats. It is one of the first to get started.
 * This thread also stores the pointer to bloom filter
 * data structure which is used for analysis.*/
struct stats_tracking {
    struct thread_storage *tstor;
    BloomFilter *bf;
	struct log_file *pkt_log;
	struct log_file *dup_pkt_log;
    int num_threads;
	int mode;
    uint64_t received_packets;
    uint64_t received_bytes;
    uint64_t socket_packets;
    uint64_t socket_drops;
    uint64_t socket_freezes;
    int verbosity;
    int *t_start_p;  /* Clean start predicate */
    pthread_cond_t *t_start_c; /* Clean start condition */
    pthread_mutex_t *t_start_m; /* Clean start mutex */
    pthread_mutex_t *log_access;
    pthread_mutex_t *bf_access;
};

/* Stores details about the thread */
struct thread_storage {
    int tnum;      /* Thread Number */
    pthread_t tid; /*Thread ID */
    pthread_attr_t thread_attributes;
    int sockfd;   /* Socket owned by this thread */
    const char *if_name; /* Name of interface to bind the socket to */
    char *output_file_name; /* Name of output file */
    uint8_t *mapped_buffer; /* The pointer to the mmap()'d region */
    struct tpacket_block_desc **block_header; /* The pointer to each block in mmap()'d region */
    struct tpacket_req3 ring_params; /* The ring allocation params to setsockopt() */
    struct stats_tracking *statst;  /* A pointer to struct with stats counters */
    double *block_streak_hist; /* Block streak histogram */
    pthread_mutex_t bstreak_m; /* Block streak mutex */
    int *t_start_p;  /* Clean start predicate */
    pthread_cond_t *t_start_c; /* Clean start condition */
    pthread_mutex_t *t_start_m;   /* Clean start mutex */
    pthread_mutex_t *log_access;
    pthread_mutex_t *bf_access;
};

#define RING_LIMITS_DEFAULT_FRAC 0.01

void ring_limits_init(struct ring_limits *rl, float frac){

    if(frac < 0.0 || frac > 1.0){
        /* sanity check */
        frac = RING_LIMITS_DEFAULT_FRAC;
    }

    /* This is the only parameter you should need to change */
    rl->af_desired_memory = (uint64_t) sysconf(_SC_PHYS_PAGES) * sysconf(_SC_PAGESIZE) * frac;
    //rl->af_desired_memory = 128 * (uint64_t) (1 << 30); /* 8 GiB */
    fprintf(stderr, "mem: %" PRIu64 "\tfrac: %f\n", rl->af_desired_memory, frac);

    /* With TPACKET_V3, the tp_frame_size value is effectively ignored
     * because packets are packed together tightly to fill up a 
     * block. There are still some restrictions but for most of
     * part changingit won't have any effect and setting it small
     * won't actually truncate any frames */

    /* Don't change following parameters without good reason */
    rl->af_ring_limit      = 0xffffffff; /* setsockopt() can't allocate more than this so don't try */
    rl->af_framesize       = 2 * (1 << 10); /* default frame size: 2 KiB. */
    rl->af_blocksize       = 4 * (1 << 20); /* 4 MiB. (must be a multiple of af_framesize) */
    rl->af_min_blocksize   = 64 * (1 << 10); /* 64 KiB */
    rl->af_target_blocks   = 64;
    rl->af_min_blocks      = 8;
    rl->af_blocktimeout    = 100;   /* milliseconds before a block is returned partially full */
    rl->af_fanout_type     = PACKET_FANOUT_LB;  /* PACKET_FANOUT_LB implements a round robin
                                                   algorithm for spreading traffic across sockets.
                                                  Since our case is only to capture packet, this can help
                                                  in load balanding of traffic */
    sniffer_debug("Initalized ring\n");
}

void af_packet_stats(int sockfd, struct stats_tracking *statst){
    sniffer_debug("Finding packet stats\n");
    int err;
    struct tpacket_stats_v3 tp3_stats;

    socklen_t tp3_len = sizeof(tp3_stats);
    err = getsockopt(sockfd, SOL_PACKET, PACKET_STATISTICS, &tp3_stats, &tp3_len);
    if(err){
        perror("error: could not get packet statistics for the given socket\n");
        return;
    }

/*    printf("\nReceived %u packets, %u dropped, freeze_q_cnt: %u\n",
        tp3_stats.tp_packets, tp3_stats.tp_drops,
	    tp3_stats.tp_freeze_q_cnt);*/

    if(statst != NULL){
        statst->socket_packets += tp3_stats.tp_packets;
        statst->socket_drops += tp3_stats.tp_drops;
        statst->socket_freezes += tp3_stats.tp_freeze_q_cnt;
    }

}

void *stats_thread_func(void *statst_arg){

    struct stats_tracking *statst = (struct stats_tracking *) statst_arg;
    int duration = 0;

    /* Stats thread is one of the first thread to get started and it has to wait for 
     * other threads. Otherwise, we will be tracking bogus stats until
     * they get up to speed. */
    int err;
    err = pthread_mutex_lock(statst->t_start_m);
    if(err != 0){
        fprintf(stderr, "%s: error locking clean start mutex for stats thread\n", 
                strerror(err));
        exit(255);
    }
    while(*(statst->t_start_p) != 1){
        err = pthread_cond_wait(statst->t_start_c, statst->t_start_m);
        if(err != 0){
            fprintf(stderr, "%s: error waiting on clean start condition for stats thread\n", 
                    strerror(err));
            exit(255);
        }
    }
    err = pthread_mutex_unlock(statst->t_start_m);
    if (err != 0){
        fprintf(stderr, "%s: error unlocking clean start mutex for stats thread\n", 
                strerror(err));
        exit(255);
    }

    char space[2] = " ";
    struct timespec ts;  /* stores time in nanosecond */
    double time_d; /* time delta */
    memset(&ts, 0, sizeof(ts));
    /*
     * Enable all signals so that this thread shuts down first
     */
    enable_all_signals();

    while(sig_close_flag == 0){
        uint64_t packets_before = statst->received_packets;
        uint64_t bytes_before = statst->received_bytes;
        uint64_t socket_packets_before = statst->socket_packets;
        uint64_t socket_drops_before = statst->socket_drops;
        uint64_t socket_freezes_before = statst->socket_freezes;
    

        (void)time_elapsed(&ts);  /* Fills out the struct with current time */

        /* We wait a second until to see whether time delta is working right or not */
        sleep(3); /* Print every three seconds */
        time_d = time_elapsed(&ts);

        if((time_d < 0.9 * 3) || (time_d > 1.1 * 3)){
            fprintf(stderr, "Unable to compute statistics because clock strayed too far from 1 second: %f seconds\n", time_d);
        }
   
        /* Collecting socket statistics */
        double tot_rusage = 0;  /* total ring(r) usage across all threads */
        double worst_rusage = 0; /* Worst average buffer usage */
        double worst_i_rusage = 0; /* Worst instantaneous ring buffer usage */
        for(int thread = 0; thread < statst->num_threads; thread++){

            af_packet_stats(statst->tstor[thread].sockfd, (struct stats_tracking *)statst);

            int thread_block_count = statst->tstor[thread].ring_params.tp_block_nr;
            double *bstreak_hist = statst->tstor[thread].block_streak_hist;

            /* Get lock for bstreak histogram computation */
            err = pthread_mutex_lock(&(statst->tstor[thread].bstreak_m));
            if(err != 0){
                fprintf(stderr, "%s: error acquiring bstream mutex lock\n",
                        strerror(err));
            }

            /* Compute total time */
            double ttot = 0;
            for(int i = 0; i <= thread_block_count; i++){
                ttot += bstreak_hist[i];

                if(bstreak_hist[i] > 0){
                    double utmp = (double) (i) / (double) thread_block_count;
                    if(utmp > worst_i_rusage){
                        worst_i_rusage = utmp;
                    }
                }
            }

            /* Computing average weighted ring usage*/
            double rusage = 0;
            if(ttot > 0){
                for(int i = 0; i <= thread_block_count; i++){
                    rusage += (bstreak_hist[i] / ttot ) * ((double)(i) / (double)thread_block_count);
                }
            }
            /* Clearing the bstreak histogram */ 
            for(int i = 0; i <= thread_block_count; i++){
                    bstreak_hist[i] = 0; 
            }

            err = pthread_mutex_unlock(&(statst->tstor[thread].bstreak_m));
            if (err != 0){
                fprintf(stderr, "%s: stats func error releasing block stream mutex lock \n",
                    strerror(err));
                exit(255);
            }

            tot_rusage += rusage;
            if (rusage > worst_rusage){
                worst_rusage = rusage;
            }
        } /* end of for loop */

        /* Per second stats scaled by time delta. These values measure number of packets/bytes/socket packets
         * received in one unit of time. */
        double pps = (statst->received_packets - packets_before) / time_d; // packets 
        double byps = (statst->received_bytes - bytes_before) / time_d; // bytes 
        double spps = (statst->socket_packets - socket_packets_before) / time_d; // socket packets 
//        printf("pps %f, byps %f, spps %f \n", pps, byps, spps); 
        /* Not scaling socket stats */
        uint64_t sdps = statst->socket_drops - socket_drops_before;
        uint64_t sfps = statst->socket_freezes - socket_freezes_before; 
    
        /* Compute the estimated Ethernet rate which accounts for the
         * "extra" per-packet data including the:
         * interpacket gap (12 bytes)
         * preamble (7 bytes)
         * start of frame delimiter (1 byte)
         * frame-check-sequence / FCS (4 bytes)
         */
        double ebips = (byps + (pps * (12 + 7 + 1 + 4))) * 8; /* in bits */
    
        /* Get the "readable" numbers */
        double r_pps;
        char *r_pps_s;
        get_readable_number_float(1000, pps, &r_pps, &r_pps_s);
        if (r_pps_s[0] == '\0') {
            r_pps_s = &(space[0]);
        }
    
        double r_byps;
        char *r_byps_s;
        get_readable_number_float(1000, byps, &r_byps, &r_byps_s);
        if (r_byps_s[0] == '\0') {
            r_byps_s = &(space[0]);
        }
    
        double r_spps;
        char *r_spps_s;
        get_readable_number_float(1000, spps, &r_spps, &r_spps_s);
        if (r_spps_s[0] == '\0') {
            r_spps_s = &(space[0]);
        }
    
        double r_ebips;
        char *r_ebips_s;
        get_readable_number_float(1000, ebips, &r_ebips, &r_ebips_s);
        if (r_ebips_s[0] == '\0') {
            r_ebips_s = &(space[0]);
        }
    
        if (statst->verbosity) {
            fprintf(stderr,
                    "Stats: "
                    "%7.03f%s Packets/s; Data Rate %7.03f%s bytes/s; "
                    "Ethernet Rate (est.) %7.03f%s bits/s; "
                    "Socket Packets %7.03f%s; Socket Drops %" PRIu64 " (packets); Socket Freezes %" PRIu64 "; "
                    "All threads avg. rbuf %4.1f%%; Worst thread avg. rbuf %4.1f%%; Worst instantaneous rbuf %4.1f%%\n",
                    r_pps, r_pps_s, r_byps, r_byps_s,
                    r_ebips, r_ebips_s,
                    r_spps, r_spps_s, sdps, sfps,
                    (tot_rusage / (statst->num_threads)) * 100.0, worst_rusage * 100.0,
                    worst_i_rusage * 100.0);
        }
    duration++;
    }
    
    return NULL; 
}

void process_all_packets_in_block(struct tpacket_block_desc *block_hdr, 
        struct stats_tracking *statst){
	/* TODO
	 * The output file name should vary with respect to mode
	 */
    int err;
    sniffer_debug("Processing packets in a block\n");
    int num_pkts = block_hdr->hdr.bh1.num_pkts, i;
    unsigned long byte_count = 0; 
	struct log_file *pkt_log = statst->pkt_log;
	struct log_file *dup_pkt_log = statst->dup_pkt_log;
	struct tpacket3_hdr *pkt_hdr;
    pkt_hdr = (struct tpacket3_hdr *) ((uint8_t *) block_hdr + block_hdr->hdr.bh1.offset_to_first_pkt);
    for (i = 0; i < num_pkts; ++i) {
        struct packet_info pi;
        /* The tp_snaplen value is the actual number of bytes of this packet
         * that made it into the ringbuffer block. A packet can be of any size. The
         * tp_snaplen field says that actual size of packet which gets captured in that
         * frame. For example, if a packet is of size 40 bytes and snaplen is of size
         * 10 bytes, then it means only the first 10 bytes are captures.
         * tp_len is the skb length which in special circumstances
         * could be more (because of extra headers from the ethernet card, truncation, etc.)
         */
        byte_count += pkt_hdr->tp_snaplen;
  
          /* Grab the times */
        pi.ts.tv_sec = pkt_hdr->tp_sec;
        pi.ts.tv_nsec = pkt_hdr->tp_nsec;
  
        pi.caplen = pkt_hdr->tp_snaplen;
        pi.len = pkt_hdr->tp_len;
        pi.is_valid = 0;
  
        uint8_t *eth = (uint8_t*)pkt_hdr + pkt_hdr->tp_mac;
        sniffer_debug("Going for extracting packet info \n");
        extract_packet_info(eth, &pi);
        sniffer_debug("Finished extracting packet info \n");
        sniffer_debug("Printing packet valid : ");
        sniffer_debug("%d\n", pi.is_valid);
        if (pi.is_valid) {
			int mode = statst->mode;
            
			BloomFilter *bf = statst->bf;

			write_packet_info(&pi, pkt_log, statst->log_access);	
			if (mode == 1) {
				/* Add hash entry to bloom filter and log packet */	
				err = pthread_mutex_lock(statst->bf_access);
                if(err != 0){
                    fprintf(stderr, "%s: error acquiring hash add lock\n",
                            strerror(err));
                } 
				cpp_add(bf, (const char *)pi.payload_hash); 
                err = pthread_mutex_unlock(statst->bf_access);
                if(err != 0){
                    fprintf(stderr, "%s: error releasing hash add lock\n",
                            strerror(err));
                } 
			} else if (mode == 2) {
				/* Add log entry to test file.
				 * Check whether hash entry is present. If not, write to 
				 * a seperate log file.  */

				/* TODO
				 * Ideally the lock here is not needed because this operation only
				 * requires read from the bloom filter */
				pthread_mutex_lock(statst->bf_access);
				int result = cpp_check(bf, (const char *)pi.payload_hash);
				pthread_mutex_unlock(statst->bf_access); 

				if (result == 1) {
					/* Hash is found in the table - a dup packet */
                    printf("Duplicate packet \n");
					write_packet_info(&pi, dup_pkt_log, statst->log_access);	
				} 
			} 
        }
		
        sniffer_debug("Going to point next packet header \n");
        pkt_hdr = (struct tpacket3_hdr *) ((uint8_t *)pkt_hdr + pkt_hdr->tp_next_offset);
        sniffer_debug("Pointer to next packet header \n");
    }
    sniffer_debug("Ending processing of packets\n");
    
    __sync_add_and_fetch(&(statst->received_packets), num_pkts);
    __sync_add_and_fetch(&(statst->received_bytes), byte_count);
 
}

int af_packet_rx_ring_fanout_capture(struct thread_storage *thread_stor){
    sniffer_debug("Thread number %d is abot to start packet capturing\n", 
            thread_stor->tnum); 
    int err;
    /* At this point this thread is ready to go but
     * we need to wait for all other threads to be
     * ready too. We'll wait on a condition broadcast
     * from the main thread to let us know we can go */
    err = pthread_mutex_lock(thread_stor->t_start_m);
    if(err!=0){
        fprintf(stderr, "%s: error locking clean start mutex for thread %lu\n",
                strerror(err), thread_stor->tid);
        exit(255);
    }
    while(*(thread_stor->t_start_p) != 1){
        err = pthread_cond_wait(thread_stor->t_start_c, thread_stor->t_start_m);
        if(err != 0){
            fprintf(stderr, "%s: error waiting on clean start condition for thread %lu\n",
                    strerror(err), thread_stor->tid);
            exit(255);
        }
    }
    err = pthread_mutex_unlock(thread_stor->t_start_m);
    if(err != 0){
        fprintf(stderr, "%s: error unlocking clean start mutex for thread %lu\n",
                strerror(err), thread_stor->tid);
        exit(255);
    }

    /* get local copies so that we need can skip pointer deferences
     * every time for use */
    int sockfd = thread_stor->sockfd;
    struct tpacket_block_desc **block_header = thread_stor->block_header;
    struct stats_tracking *statst = thread_stor->statst;
    double *block_streak_hist = thread_stor->block_streak_hist;
    pthread_mutex_t *bstreak_m = &(thread_stor->bstreak_m);

    /* We got clean start all clear so we can get started but while
     * we are waiting out socket was filling up with packets and drops 
     * were accumulating. So, we need to return everything to kernel. */
    uint32_t thread_block_count = thread_stor->ring_params.tp_block_nr;
    af_packet_stats(sockfd, NULL); //Discard bogus stats
  /* 
   * The kernel initializes all frames to TP_STATUS_KERNEL, when the kernel
   * receives a packet it puts in the buffer and updates the status with
   * at least the TP_STATUS_USER flag. Then the user can read the packet,
   * once the packet is read the user must zero the status field, so the kernel 
   * can use again that frame buffer.
   * Reference docs: https://www.kernel.org/doc/Documentation/networking/packet_mmap.txt
   */
    for(unsigned int b = 0; b < thread_block_count; ++b){
        if((block_header[b]->hdr.bh1.block_status & TP_STATUS_USER) == 0){
            continue;
        } else {
            block_header[b]->hdr.bh1.block_status = TP_STATUS_KERNEL;
        }
    }
    af_packet_stats(sockfd, NULL);
    
    fprintf(stderr, "Thread %d with thread id %lu started\n", thread_stor->tnum,
            thread_stor->tid);

    /* The kernel keeps a pointer to one of the blocks in the ringbuffer 
     * (starting at 0) and every time the kernel fills a block and 
     * returns it to the userspace (by setting block status to TP_STATUS_USER)
     * the kernel increments (module the number of block) the block pointer.
     * See the diagram 'Vanilla PF_RING' here: https://www.ntop.org/products/packet-capture/pf_ring/
     * for a rough idea.
     *
     * Now the kernel points to a block with TP_STATUS_KERNEL (ideally, an empty block).
     * A tricky part is that if the kernel's block pointer ends up pointing at a block
     * that isn't marked TP_STATUS_KERNEL, the kernel will freeze the queue and discard
     * the packet until the block it is pointing is returned back to the kernel. See
     * https://github.com/torvalds/linux/blob/master/net/packet/af_packet.c for 
     * details on queue freezing behavior. // TODO
     *
     * This means that in a worst-case scenario, only a single block in the 
     * ringbuffer could be marked for userspace and the kernel could get stuck on 
     * that block and throw away packets even though the other blocks in ringbuffer are free.
     * The kernel DOES NOT go in search for free blocks if the current one is taken. 
     * It waits until the current one is released.
     *
     * The following loop tries to keep the current block (cb) pointed to the block
     * that the kernel is about to return and then increment to the next block the kernel will
     * return and so forth. If for some reason they get out of sync, the kernel can get stuck and
     * freeze the queue while we can get stuck trying to check the wrong block to see
     * if it has returned yet.
     *
     * To address this case, we count how many times poll() has returned saying that 
     * data is ready (pstreak) but we haven't gotten any new data. If this happens few
     * times in a row, we're checking the wrong block and the kernel has frozen the queue
     * and is stuck on another block. The fix is to increment our block pointer to go 
     * find the block the kernel is stuck on. This will quickly move the thread and 
     * the kernel back into sync.
     */
    
     struct pollfd psockfd;
     memset(&psockfd, 0, sizeof(psockfd));
     psockfd.fd = sockfd;
     psockfd.events = POLLIN | POLLERR;
     psockfd.revents = 0;

     int pstreak = 0; /* The number of times in a row (streak) poll() has told us there is data */
     uint64_t bstreak = 0; /* Number of blocks we have gotten in a row without poll() */
     int polret; /* Return value from poll() */

     unsigned int cb = 0; /* Current block pointer */
     struct timespec ts;
     (void)time_elapsed(&ts); /* Initializes ts with current time */
     double time_d; /* time delta */

     while(sig_close_workers == 0){
        /* Check whether the 'user' bit is set or not on the block. 
         * If the bit is set, the block has been filled by the kernel and
         * now we should process the block. Otherwise, the block is still owned 
         * by the kernel and we should wait.
         */

         if((block_header[cb]->hdr.bh1.block_status & TP_STATUS_USER) == 0){

             /*This branch is for 'user' bit not set meaning the kernel is 
              * still filling up the block with new packets */

             /* Track number of blocks in a row in this streak */
             time_d = time_elapsed(&ts); /* How long the streak lasted */

             if(bstreak > thread_block_count){
                 bstreak = thread_block_count;
             }

             /* TODO Is mutex lock really needed or can it be skipped? */
             err = pthread_mutex_lock(bstreak_m);
             if(err != 0){
                 fprintf(stderr, "%s: error acquiring bstreak mutex lock \n", strerror(err));
                 exit(255);
             } 

             block_streak_hist[bstreak] += time_d;
             err = pthread_mutex_unlock(bstreak_m);
             if(err != 0){
                 fprintf(stderr, "%s: error releasing bstreak mutex unlock \n", strerror(err));
                 exit(255);
             } 

             bstreak = 0;

             /* If poll() has returned but we haven't found any data .. */
             if(pstreak > 2){
                 /* Since poll() is telling us that there is data but we aren't 
                  * seeing it in the current block our current block pointer 
                  * should be out of sync with the kernel's. so we should probe 
                  * all the blocks and reset our pointer to the first filled block. */
                 for(uint32_t i = 0; i < thread_block_count; ++i){
                     if((block_header[i]->hdr.bh1.block_status & TP_STATUS_USER) != 0){
                         cb = i;
                         break; /* stopping at first block round */
                     }
                 }
             }

             /* polling the kernel when the data is returned */
             polret = poll(&psockfd, 1, 1000); /* letting poll wait up to a second */
             if(polret < 0){
                perror("poll returned error\n");
             } else if(polret == 0){
                 /* No packets at the moment. (timeout) */
             } else {
                pstreak++;
             }
             
         } else {
             
             /* In this branch, the bit is set meaning the kernel has filled this block 
              * and returned it to us for processing */
             bstreak++;

             /* We found data. Process it */ 
             process_all_packets_in_block(block_header[cb], statst); 
             
             /* Reset accounting */
             pstreak = 0;
              
             /* return this block to the kernel */
             block_header[cb]->hdr.bh1.block_status = TP_STATUS_KERNEL;

             cb += 1;
             cb = cb % thread_block_count;
             
         }
     } /* End of while */
     fprintf(stderr, "Thread %d with thread id %lu exiting \n",
             thread_stor->tnum, thread_stor->tid);
     return 0;
}

void *packet_capture_thread_func(void *arg){
    struct thread_storage *thread_stor = (struct thread_storage *)arg;
    /*
     * Disabling all signals so that this worker thread is not disturbed
     * in middle of packet processing.
     */
    disable_all_signals();

    /* performing packet processing */
    if(af_packet_rx_ring_fanout_capture(thread_stor) < 0){
        fprintf(stdout, "error: could no perform packet capture \n");
        exit(255);
    }
    return NULL;
}


/* Creation of dedicated AF_PACKET TPACKETv3 socket. Reference docs:
 * https://www.kernel.org/doc/Documentation/networking/packet_mmap.txt
 */
int create_dedicated_socket(struct thread_storage *thread_stor, int fanout_arg){
    sniffer_debug("Creating dedicated socket \n");
    int err;
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP)); /* Capturing only IP Packet */
    if(sockfd == -1){
        fprintf(stderr, "Could not create dedicated socket \n");
        return -1;
    }
    /* Now store this socket file descriptor in thread storage */
    thread_stor->sockfd = sockfd;

    /* set AF_PACKET version to v3 since it performs better 
     * by reading blocks of packet and not single packet. 
     * PACKET_VERSION is defined in linux/if_packet.h */
    int version = TPACKET_V3;
    err = setsockopt(sockfd, SOL_PACKET, PACKET_VERSION, &version, sizeof(version));
    if(err){
        fprintf(stderr, "could not set socket to tpacket_v3 version\n");
        return -1;
    }
    
    /* get interface number on which we want to capture the traffic
     * if_nametoindex defined in net/if.h  */
    int interface_number = if_nametoindex(thread_stor->if_name);
    if(interface_number == 0){
        fprintf(stderr, "Can't get interface number for interface %s\n", thread_stor->if_name);
        return -1;
    }

    /* setting interface to promiscous mode. Promiscous mode
     * passes all traffic to kernel. packet_mreq defined in linux/if_packet.h */
    struct packet_mreq sock_params;
    memset(&sock_params, 0, sizeof(sock_params));
    sock_params.mr_type = PACKET_MR_PROMISC;
    sock_params.mr_ifindex = interface_number;
    err = setsockopt(sockfd, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
            (void*)&sock_params, sizeof(sock_params));
    if(err){
        fprintf(stderr, "coud not set socket in promiscous mode for thread number %d\n", -1);
        return -1;
    }

    /*
     * set up RX_RING 
     */
    fprintf(stderr, "Requesting PACKET_RX_RING with %u bytes (%d blocks of size %d) for thread %d\n",
            thread_stor->ring_params.tp_block_size * thread_stor->ring_params.tp_block_nr,
            thread_stor->ring_params.tp_block_nr, thread_stor->ring_params.tp_block_size, 0);
    err = setsockopt(sockfd, SOL_PACKET, PACKET_RX_RING, 
            (void*)&(thread_stor->ring_params), sizeof(thread_stor->ring_params));
    if(err == -1){
        fprintf(stderr, "could not create PACKET_RX_RING socket");
        return -1;
    }

    /* creating the mapped buffer region. Each thread has it's own mapped buffer region. */
    uint8_t *mapped_buffer = (uint8_t *)mmap(NULL, 
              thread_stor->ring_params.tp_block_size * thread_stor->ring_params.tp_block_nr,
              PROT_READ | PROT_WRITE, MAP_SHARED | MAP_LOCKED, sockfd, 0);
    if(mapped_buffer == MAP_FAILED){
        fprintf(stderr, " mmap failed for thread number %d", 0);
        return -1;
    }
   
    /* Storing the mmap()'d region in thread storage */
    thread_stor->mapped_buffer = mapped_buffer;

    /* A capture contain many blocks. tpacket_block_desc holds 
     * an array of pointers to the start of each block struct */
    struct tpacket_block_desc **block_header = (struct tpacket_block_desc**)malloc(thread_stor->ring_params.tp_block_nr * sizeof(struct tpacket_hdr_v1 *)); 
    if(block_header == NULL){
       fprintf(stderr, "error: cound not allocate block_header pointer array for thread %d\n", 0);
    }

   /* Storing the block_header pointer array in thread storage */
    thread_stor->block_header = block_header;

    for(unsigned int i = 0; i < thread_stor->ring_params.tp_block_nr; ++i){
        block_header[i] = (struct tpacket_block_desc *)(mapped_buffer + (i * thread_stor->ring_params.tp_block_size));
    }

   /* bind to interface */
    struct sockaddr_ll bind_address;
    memset(&bind_address, 0, sizeof(bind_address));
    bind_address.sll_family = AF_PACKET;
    bind_address.sll_protocol = htons(ETH_P_ALL);
    bind_address.sll_ifindex = interface_number;
    err = bind(sockfd, (struct sockaddr*)&bind_address, sizeof(bind_address));
    if(err){
        fprintf(stderr, "could not bind interface %s to AF_PACKET socket for thread %d\n", 
                thread_stor->if_name, 0);
        return -1;
    }

    /* verifying that interface number matches requested interface  */
    char actual_ifname[IF_NAMESIZE];
    char *retval = if_indextoname(interface_number, actual_ifname);
    if(retval == NULL){
        fprintf(stderr, "%s: could not get interface name \n", strerror(errno));
        return -1;
    } else {
        if(strncmp(actual_ifname, thread_stor->if_name, IF_NAMESIZE) != 0){
            fprintf(stderr, "error: interface name %s does not match the requested interface name %s\n",
                    actual_ifname, thread_stor->if_name);
        }
    }

    /* set up fanout. fanout is used to distirbute packets to process
     * across threads. Each thread get some number of packets based
     * on the fanout technique. */

    err = setsockopt(sockfd, SOL_PACKET, PACKET_FANOUT, &fanout_arg, sizeof(fanout_arg));
    if(err){
        fprintf(stderr, "error: could not configure fanout\n");
        return -1;
    }
    return 0;
}

/* Initializes thread, assigns socket, mapped buffer and other
 * thread requirements, dispatches the thread */
enum status bind_and_dispatch(struct sniffer_config *cfg){
    /* initialiing ring limits */
    sniffer_debug("Binding sockets and dispatching thread\n");
    struct ring_limits rl;
    ring_limits_init(&rl, cfg->buffer_fraction);

    int err;
    int num_threads = cfg->num_threads;
    int fanout_arg = ((getpid() & 0xffff) | (rl.af_fanout_type << 16));

    /* All our threads has to clean start at the same time or else
     * some thread start working before other threads are ready and this 
     * makes a mess of drop counters and gets in the way of dropping privs 
     * and other such things that need to happen in a coordingated manner.
     * We pass a pointer to these via the thread storage struct */
    
    int t_start_p = 0;
    pthread_cond_t t_start_c = PTHREAD_COND_INITIALIZER;
    pthread_mutex_t t_start_m = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_t log_access = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_t bf_access = PTHREAD_MUTEX_INITIALIZER;

    struct stats_tracking statst;
    memset(&statst, 0, sizeof(statst));
    statst.num_threads = num_threads;
    statst.t_start_p = &t_start_p;
    statst.t_start_c = &t_start_c;
    statst.t_start_m = &t_start_m;
    statst.log_access = &log_access;
    statst.bf_access = &bf_access;
    if(cfg->verbosity == 1){
        statst.verbosity = 1;
    }

    statst.mode = cfg->mode;

    statst.pkt_log = (struct log_file *)malloc(sizeof(struct log_file));
	memset(statst.pkt_log, 0, sizeof(struct log_file));
	statst.pkt_log->pkt_count = 0;
	strcpy(statst.pkt_log->dirname, cfg->logdir);
	strcpy(statst.pkt_log->filename, "");
	time_t rawtime;
	time(&rawtime);
	sprintf(statst.pkt_log->filename, "%slog%ld.json", statst.pkt_log->dirname, rawtime);
	statst.pkt_log->mode = 1;

	statst.dup_pkt_log = (struct log_file *)malloc(sizeof(struct log_file));
	memset(statst.dup_pkt_log, 0, sizeof(struct log_file));
	statst.dup_pkt_log->pkt_count = 0;
	strcpy(statst.dup_pkt_log->dirname, cfg->logdir);
	strcpy(statst.dup_pkt_log->filename, "");
	sprintf(statst.dup_pkt_log->filename, "%sdup_pkt_log%ld.json", 
			statst.dup_pkt_log->dirname, rawtime);
	statst.dup_pkt_log->mode = 2;
    printf("Intialized duplicate log file. \nfilename: %s directory name: %s mode: %d \n",
           statst.dup_pkt_log->filename, statst.dup_pkt_log->dirname, statst.dup_pkt_log->mode);

    BloomFilter *bf = cpp_create_bloom_filter();
    if(!bf){
        perror("could not allocate memory for bloom filter\n");
        exit(255);
    }
    
    if (statst.mode == 2){
        /* Perform detection */ 
		cpp_load(bf);
        printf("Loaded bloom filter ");
    } 
        
    statst.bf = bf;
	
    struct thread_storage *tstor; // pointer to array of struct thread_storage, one for each thread 
    tstor = (struct thread_storage *)malloc(num_threads * sizeof(struct thread_storage));
    if(!tstor){
        perror("could not allocate memory for struct thread storage array\n");
    }
    statst.tstor = tstor;

    /* Now that we know the number of threads we have, we need
     * to figure out ring paramters */
    uint32_t thread_ring_size;
    if(rl.af_desired_memory / num_threads > rl.af_ring_limit) {
        thread_ring_size = rl.af_ring_limit;
        fprintf(stderr, "Notice: desired memory exceeds %lx memory for %d threads\n",
                rl.af_ring_limit, num_threads);
    } else {
        thread_ring_size = rl.af_desired_memory / num_threads;
    }

    /* If the number of blocks is fewer than our target,
     * decrease the block size to increase block count */
    uint32_t thread_ring_blocksize = rl.af_blocksize;
    while(((thread_ring_blocksize >> 1) >= rl.af_min_blocksize) &&
            (thread_ring_size / thread_ring_blocksize < rl.af_target_blocks)){
        thread_ring_blocksize = thread_ring_blocksize >> 1; /* Halve the block size */
    }

    uint32_t thread_ring_blockcount = thread_ring_size / thread_ring_blocksize;
    if (thread_ring_blockcount < rl.af_min_blocks){
        fprintf(stderr, "Error: only able to allocate %u blocks per thread (minimum %lu)\n",
                thread_ring_blockcount, rl.af_min_blocks);
        exit(255);
    }

    /* blocks must be a multiple of frame size */
    if(thread_ring_blocksize % rl.af_framesize != 0){
        fprintf(stderr, "Error: blocksize not a multiple of frame size");
        exit(255);
    }
    
    if((uint64_t)num_threads * (uint64_t)thread_ring_blockcount * (uint64_t)thread_ring_blocksize < rl.af_desired_memory){
        fprintf(stderr, "Notice: requested memory will be less than desired memory\n");
    }

    /*Fill out ring request struct */
    struct tpacket_req3 thread_ring_req;
    memset(&thread_ring_req, 0, sizeof(thread_ring_req));
    thread_ring_req.tp_block_size = thread_ring_blocksize;
    thread_ring_req.tp_frame_size = rl.af_framesize;
    thread_ring_req.tp_block_nr = thread_ring_blockcount;
    thread_ring_req.tp_frame_nr = (thread_ring_blocksize * thread_ring_blockcount) / rl.af_framesize;
    thread_ring_req.tp_retire_blk_tov = rl.af_blocktimeout;
    thread_ring_req.tp_feature_req_word = TP_FT_REQ_FILL_RXHASH;

    /* Get all threads and allocate socket */
    for(int thread = 0; thread < num_threads; thread ++){

        /* Initialise the thread */
        tstor[thread].tnum = thread;
        tstor[thread].tid = 0;
        tstor[thread].sockfd = -1;
        tstor[thread].if_name = cfg->capture_interface;
		// tstor[thread].output_file_name = cfg->output_file_name;
        tstor[thread].statst = &statst;
        tstor[thread].t_start_p = &t_start_p;
        tstor[thread].t_start_c = &t_start_c;
        tstor[thread].t_start_m = &t_start_m;
        tstor[thread].log_access = &log_access;
        tstor[thread].bf_access = &bf_access;

        err = pthread_attr_init(&(tstor[thread].thread_attributes));
        if (err){
            fprintf(stderr, "%s: error initializing attributes for thread %d\n", 
                    strerror(err), thread);
            exit(255);
        }

        pthread_mutexattr_t m_attr;
        err = pthread_mutexattr_init(&m_attr);
        if (err) {
            fprintf(stderr, "%s: error initializing block streak mutex attributes for thread %d\n",
                    strerror(err), thread);
            exit(255);
        }

        tstor[thread].block_streak_hist = (double *)calloc(thread_ring_blockcount + 1, sizeof(double));
        if(!tstor[thread].block_streak_hist){
            perror("could not allocate memory for thread stats block streak histogram \n");
        }

        memcpy(&(tstor[thread].ring_params), &thread_ring_req, sizeof(thread_ring_req));

        err = create_dedicated_socket(&(tstor[thread]), fanout_arg);
        if(err != 0){
            fprintf(stderr, "error creating socket for thread %d\n", thread);
            exit(255);
        }
    }
    /* Initialize frame handers */
    // TODO 
    
    // Initializing timer thread
    pthread_t timer_thread;
    int timeout_time = cfg->time_delta;
    if(timeout_time > 0){
        pthread_attr_t attr;
        int err;
        err = pthread_attr_init(&attr);
        if(err != 0)
            fprintf(stderr, "Error occured in initializing thread attributes \n");
        pthread_create(&timer_thread, &attr, track_time, &timeout_time);
    }
    
    /* Stats thread is the first thread to be started */
    pthread_t stats_thread;
    err = pthread_create(&stats_thread, NULL, stats_thread_func, &statst);
    if(err != 0){
        perror("error creating stats thread\n");
    }

    for(int thread = 0; thread < num_threads; ++thread){
        pthread_attr_t thread_attributes;
        err = pthread_attr_init(&thread_attributes);
        if (err){
            fprintf(stderr, "%s: error initializing attributes for thread %d\n",
                    strerror(err), thread);
            exit(255);
        }
        
        err = pthread_create(&(tstor[thread].tid), &thread_attributes,
               packet_capture_thread_func, &(tstor[thread]));
       if (err){
            fprintf(stderr, "%s: error creating af_packet capture thread %d\n",
                    strerror(err), thread);
            exit(255);
       }
    }

    /* At this point all threads are started but they are waiting 
     * for clean start condition */
    t_start_p = 1;
    err = pthread_cond_broadcast(&t_start_c); // Wake up all waiting threads
    if(err != 0){
        printf("%s: error broadcasting all clear on clean start condition\n",
                strerror(err));
        exit(255);
    }

    /* Waiting for stats thread to close (happens only
     * on SIGINT/SIGTERM */
    pthread_join(stats_thread, NULL);

    /* Let workers thread know that stats tracking closed */
    sig_close_workers = 1;

    /* Wait for each thread to exit */
    for(int thread = 0; thread < num_threads; ++thread){
        pthread_join(tstor[thread].tid, NULL);
    }

    /* Free up resources */
    for(int thread = 0; thread < num_threads; ++thread){
        free(tstor[thread].block_header);
        munmap(tstor[thread].mapped_buffer, 
                tstor[thread].ring_params.tp_block_size * tstor[thread].ring_params.tp_block_nr);
        free(tstor[thread].block_streak_hist);
        close(tstor[thread].sockfd);
    }

    free(tstor);
    printf("Closed all threads \n");
    sniffer_debug("Closed all threads. Printing packet statistics\n");

    fprintf(stderr, "--\n"
      "%" PRIu64 " packets captured\n"
      "%" PRIu64 " bytes captured\n"
      "%" PRIu64 " packets seen by socket\n"
      "%" PRIu64 " packets dropped\n"
      "%" PRIu64 " socket queue freezes\n",
      statst.received_packets, statst.received_bytes, statst.socket_packets, statst.socket_drops, statst.socket_freezes);
  
	if(statst.mode == 1){
		/* Write bloom filter */
        cpp_write(bf);
/*	    FILE *fp = fopen("bloomfilter.data", "wb");
        if(fp != NULL){
            fwrite(bf, bloom_filter_size(), 1, fp);
            fclose(fp);
        }    */
	}

    /* Control reaches here only if interrupt is pressed 
     * before timeout */ 
    if(timeout_time > 0){
        pthread_kill(timer_thread, SIGKILL);
    }
    return status_ok;
}
