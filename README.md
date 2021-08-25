## Packet Sniffer

An application which extracts payload and computes sha512 digest of the payload using
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

For capturing in interface eno1:   `./sniffer -c eno1`

For using 2 threads: `./sniffer -T 2`

For capturing upto 10 seconds: `./sniffer -t 10`

For choosing output json file name: `./sniffer -j output.json`

For help: `./sniffer -h`

For duplicate packet detection, to build index for bloom filter
run the application in mode 1 and to perform detection, rerun it in mode 2.
```
./sniffer -m 1  # building bloom filter index
./sniffer -m 2  # performing detection
```
BloomFilter is a probabilistic data structure. Given that the application
needs to capture `n` packets at a false positive rate of `e`, the configuration can be
set as
```
./sniffer -m 1 -n 10000 -e 0.001
```
The same configuration should be used during testing.
