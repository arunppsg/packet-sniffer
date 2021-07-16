# makefile for packet-sniffer
#
# Usage
# make                # compile all binary
# make clean          # remove ALL binaries and object

.PHONY = all clean

CXX     = g++
CC      =  gcc
CFLAGS  = -lpcap # for pcap.h 
CFLAGS  += -lcrypto # for sha512.h
CFLAGS  += -lpthread # for pthread.h
CFLAGS  += -Wall
CFLAGS  += -g

SNIFFERC  =  sniffer.c
SNIFFERC  += af_packet_v3.c
SNIFFERC  += sha512.c
SNIFFERC  += json_file_io.c
SNIFFERC  += pkt_processing.c
SNIFFERC  += signal_handling.c
SNIFFERC  += utils.c

SNIFFER_H = sniffer.h
SNIFFER_H += af_packet_v3.h
SNIFFER_H += sha512.h
SNIFFER_H += pkt_processing.h
SNIFFER_H += json_file_io.h
SNIFFER_H += signal_handling.h
SNIFFER_H += utils.h

SNIFFER_OBJ = $(SNIFFERC:%c=%o)

%.o: %.c %.h
	$(CC) $(CFLAGS) -c $<

.PHONY: all
all: clean sniffer.o

#sniffer.o: $(SNIFFER_OBJ) $(SNIFFER_H)
#	$(CC) $(CFLAGS) sniffer.c $(SNIFFER_OBJ)  -o sniffer.o

sniffer.o: $(SNIFFERC) $(SNIFFER_H)
	$(CC) $(SNIFFERC) $(CFLAGS) -o sniffer.o

#sniffer.o sniffer.c 
#sniffer.o: $(SNIFFERC) $(SNIFFER_H)
#	$(CC) $(SNIFFERC) $(CFLAGS) -o ../analysis/sniffer.o

debug-sniffer: CFLAGS += -DDEBUG
debug-sniffer: clean sniffer.o

.PHONY: clean
clean:
	rm -f sniffer.o *.json
