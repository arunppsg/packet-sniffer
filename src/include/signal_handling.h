/*
 * signal_handling.h 
 */

#ifndef SIGNAL_HANDLING_H
#define SIGNAL_HANDLING_H

#include <signal.h>
#include "sniffer.h"  /* for enum status */
extern int sig_close_fag; /* Watch by threads while processing packets */

void sig_close (int sig_close_arg);

enum status setup_signal_handler(void);

void enable_all_signals(void);

void disable_all_signals(void);

void *track_time(void *);
#endif /* SIGNAL_HANDLING_H */
