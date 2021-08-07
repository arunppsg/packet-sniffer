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
#CFLAGS 	+= -DDEBUG

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

SNIFFERCC = bloom_filter.cc

all: sniffer 
#$(CXX) -o sniffer.o *.o

sniffer: bf.o jfi.o apv3.o pp.o sha.o sh.o u.o s.o
	$(CXX) -o sniffer *.o $(CFLAGS)

bf.o: 
	$(CXX) -c bloom_filter.cc -Wall -o bloom_filter.o 
s.o: 
	$(CC) -c sniffer.c $(CFLAGS) -o sniffer.o

apv3.o: 
	$(CC) -c af_packet_v3.c $(CFLAGS) -o af_packet_v3.o

pp.o:
	$(CC) -c pkt_processing.c $(CFLAGS) -o pkt_processing.o

jfi.o:
	$(CC) -c json_file_io.c $(CFLAGS) -o json_file_io.o

sha.o:
	$(CC) -c sha512.c $(CFLAGS) -o sha512.o

u.o:
	$(CC) -c utils.c $(CFLAGS) -o utils.o

sh.o:
	$(CC) -c signal_handling.c $(CFLAGS) -o signal_handling.o

sniffer.o: $(SNIFFERC) $(SNIFFER_H)
	$(CC) $(SNIFFERC) $(CFLAGS) -o sniffer.o

debug-sniffer: CFLAGS += -DDEBUG
debug-sniffer: clean sniffer.o

.PHONY: clean
clean:
	rm -f *.o *.json

clean-json:
	cd output
	rm -f *.json
	cd ~
