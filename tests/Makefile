CXX     = g++
CC      =  gcc
CFLAGS  += -lpthread # for pthread.h
CFLAGS  += -Wall
CFLAGS  += -g

TESTC =  tcp_flood.c
TESTC += generate_packet.c

TESTH = tcp_flood.h
TEST_H += generate_packet.h


TEST_OBJ = $(TESTC:%c=%o)

%.o: %.c %.h
	$(CC) $(CFLAGS) -c $<

.PHONY: all
all: clean test.o

test.o: $(TESTC) $(TEST_H)
	$(CC) $(TESTC) $(CFLAGS) -o test.o

debug-test: CFLAGS += -DDEBUG
debug-test: clean test.o

.PHONY: clean
clean:
	rm -f *.o *.json

clean-json:
	rm -f *.json
                                
