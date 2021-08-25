# makefile for packet-sniffer
#
# Usage
# make                # compile all binary
# make clean          # remove ALL binaries and object

.PHONY = all clean

CXX     = g++
CC      =  gcc
CFLAGS  = -lpcap # for include/pcap.h 
CFLAGS  += -lcrypto # for include/sha512include/.h
CFLAGS  += -lpthread # for include/pthread.h
CFLAGS  += -Wall
CFLAGS  += -g
CFLAGS += -ggdb3
#CFLAGS 	+= -DDEBUG

SNIFFERC  =  sniffer.c
SNIFFERC  += af_packet_v3.c
SNIFFERC  += sha512.c
SNIFFERC  += json_file_io.c
SNIFFERC  += pkt_processing.c
SNIFFERC  += signal_handling.c
SNIFFERC  += utils.c

SNIFFER_H = include/sniffer.h
SNIFFER_H += include/af_packet_v3.h
SNIFFER_H += include/sha512.h
SNIFFER_H += include/pkt_processing.h
SNIFFER_H += include/json_file_io.h
SNIFFER_H += include/signal_handling.h
SNIFFER_H += include/utils.h

SNIFFERCC = bloom_filter.cc

C_OBJECTS = sniffer.o af_packet_v3.o pkt_processing.o json_file_io.o \
			sha512.o utils.o signal_handling.o
CXX_OBJECTS = bloom_filter.o

#Refer:include/ https://www.gnu.org/software/make/manual/include/make.html#Pattern-Examples
%.o: %.c
	$(CC) -c $< -o $@ $(CFLAGS) 

all: sniffer 

sniffer: $(CXX_OBJECTS) $(C_OBJECTS) 
	$(CXX) -o sniffer $(CXX_OBJECTS) $(C_OBJECTS) $(CFLAGS)

af_packet_v3.o: include/signal_handling.h include/sniffer.h include/pkt_processing.h \
	include/json_file_io.h include/utils.h include/bloom_filter.h
pkt_processing.o: include/sniffer.h include/sha512.h include/pkt_processing.h
json_file_io.o: include/sniffer.h include/bloom_filter.h include/json_file_io.h
sha512.o: include/sha512.h
signal_handling.o: include/signal_handling.h
utils.o: include/utils.h
bloom_filter.o: include/bloom_filter.h

debug-sniffer: CFLAGS += -DDEBUG
debug-sniffer: clean sniffer.o

.PHONY: clean
clean:
	rm -f *.o *.json *.data
	rm sniffer

.PHONY: clean-json
clean-json:
	cd output
	rm -f *.json
	cd ~
