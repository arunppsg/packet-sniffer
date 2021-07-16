/*
 * signal_handling.c
 *
 * This software defines signal extraction from Cisco Mercury
 * See: https://github.com/cisco/mercury/
 */

#include <stdio.h>
#include <pthread.h>
#include <string.h>
#include <errno.h>
#include "signal_handling.h"

int sig_close_flag = 0; /* Watched by threads while processing packets */

/*
 * sig_close() causes shutdown of program after receiving appropraite signals.
 * It shuts all the threads, then stats thread and ends the program. 
 */
void sig_close(int signal_arg){
    psignal(signal_arg, "\nShutting down");
    sig_close_flag = 1; /* tells all thread to shutdown gracefully */
    fclose(stdin);
}

/*
 * set up signal handlers 
 */
enum status setup_signal_handler(void){
    /* Ctrl-C causes graceful shutdown */
    if(signal(SIGINT, sig_close) == SIG_ERR){
        printf("Received interrupt signal \n");
        return status_err;
    }

    /* kill -15 causes graceful shutdown */
    if(signal(SIGTERM, sig_close) == SIG_ERR){
        return status_err;
    }

    return status_ok;
}


/*
 * Enable all signals
 */
void enable_all_signals(void){
    sigset_t signal_set;
    sigfillset(&signal_set);
    if(pthread_sigmask(SIG_UNBLOCK, &signal_set, NULL) != 0){
        fprintf(stderr, "%s error in pthread_sigmask unblocking signals\n",
                strerror(errno));
    }
}

/*
 * Disable all signals
 */
void disable_all_signals(void){
    sigset_t signal_set;
    sigfillset(&signal_set);
    if(pthread_sigmask(SIG_BLOCK, &signal_set, NULL) != 0){
        fprintf(stderr, "%s error in pthread_sigmask blocking signals\n",
                strerror(errno));
    }
}
