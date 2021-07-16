## Packet Sniffer

An application which extracts payload and computes payload hash using
sha256 digest of the payload from live traffic.

## ToDo:

- [ ] Add TCP flags in extraction
- [ ] Profiling 
- [ ] Add functonality for passing command line arguments - interface, num of threads, time limit for capturing etc
- [ ] Error checking
- [ ] Checkout xxhash
- [ ] Doxygen based documentation

## Usage
```
cd src
make
sudo ./sniffer.o eth0 # the interface in which packets are received
```



