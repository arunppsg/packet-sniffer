## Packet Sniffer

An application which extracts payload and computes payload hash using
sha256 digest of the payload from live traffic.

The code under `src` has the packet sniffer application. It can capture upto 
10^5 packets/sec (tested using `nping`).

The code under `test` contains code for generation of high speed packets. It is 
currently under development.

## Usage
```
cd src
make
sudo ./sniffer.o -c eth0 # the interface in which packets are received
```

## Examples:

For capturing in interface eno1:   `./sniffer.o -c eno1`

For using 2 threads: `./sniffer.o -T 2`

For capturing upto 10 seconds: `./sniffer.o -t 10`

For choosing output json file name: `./sniffer.o -j output.json`

For help: `./sniffer.o -h`


