# Packet Capture using Ring Buffers and Memory Map techniques

Traditional packet capture approaches uses `libpcap` - the packet capture 
library. The capture process using `libpcap` for high speed network traffic is very 
inefficient because of the following reasons:
 - During packet capture, if the packets are delivered as soon as they arrive, the application
capturing packets will be woken up for each packet and might have to make one or more calls to
the operating system to fetch each packet. If instead packets are not delivered as soon as they
arrive but are accumulated in a buffer and delivered after a short delay, the CPU overhead could be 
reduced since each system call delivers multiple packet. Packets that arrive are stored in a buffer and
only on some platforms the buffer size could be set. If the buffer size is too small and too many packets 
are being captured, pcakets could be dropped if the buffer fills up before the application 
read the packets. PACKET_MMAP (the packet memory map technique) allows user to set 
their own buffer size resulting in more efficient capture. 

 - The second reason is that packets are received in kernel space and process runs in 
user space. All the user analysis are done in the user space. Once the kernel receives a 
packet from the network interface, it then looks for process which are requiring the packet and
delivers the packet to that process. This approach is highly inefficient to capture high speed traffic 
because too much CPU time will be consumed in the heavy I/O operations. By using a shared buffer
between the kernel and user space (memory mapped region), one can minimize copying of 
packets from kernel space to user space. Reading process just needs to wait for the 
packets to be written in the shared ring buffers.

## The Ring Buffer Structure

A ring buffer contains many blocks onto which the packets are written. Each block is a 
continuous region of physical memory. A block contains many frames. Block sizes are always 
multiple of frame sizes. A frame is the smallest unit. A frame contains two parts - tpacket_hdr, 
data buffer. The tpacket_hdr is a struct which contains details 
about the packet and the status of this frame. It contains meta information about the 
packet like timestamp, snaplen of capture and most importantly, the offset to next packet header. 
It is defined in the header file linux/if_packet.h
The data buffer is what which actually contains the packet that is sent over the network interface.
 
## Memory Mapping and using circular ring buffer

Mapping is done by calling the conventional `mmap` function. The socket is configured
to write the packets in a memory mapped ring buffer. Once the set up
is ready, the user reads packets from the memory mapped buffer. This helps in 
avoiding packet copies and reducing the number of system calls for accessing the packets.
The user reads the packets block wise. Once the packet starts
arriving into the ring, the user can either continously keep checking for new packets
or leave the work to operating system by using `poll()` utility. 

## TPACKET_V3

Ring buffer associated with the socket can have three configurations using the `setsockopt()` function.
A socket can have be of any of the three TPACKET versions. Version 1 is the default ring buffer version. 
A few advantages of using TPACKET_V3 is that polling works on a per block basis instead of per ring basis as in the earlier
version. It is said that TPACKET_V3 utilizes 15 - 20% less CPU usage and has a higher packet capture rate.

For more details about other versions, one can read about them ![here](https://www.kernel.org/doc/Documentation/networking/packet_mmap.txt).

## Setting up Packet Capture Interface

These are the main steps in setting up the capture process:
 - Create a socket
 - Allocate circular ring buffer
 - Memory map the allocatd ring buffer to user process
 - Wait for incoming packets and capture them
 - Process the packets as your requirements
 - Close the capture socket and deallocate all resources

Sockets are created using the `socket()` utility. We create an AF_PACKET socket.
Once a socket it created, we set the TPACKET version as 3. The ring buffer is set using
a call to `setsockopt()` function with the option PACKET_RX_RING and ring properties.
Once the socket and the ring buffer is setup, we create a memory mapped region
with the socket file descriptor and ring size as input arguments. The ring size is the
number of blocks in the ring multiplied by size of block. These values are configurable. 
The socket is then binded to an interface and in case we are using multiple sockets for
capture, we can use PACKET_FANOUT option to distributed packets across sockets.

The kernel initializes all blocks to TP_STATUS_KERNEL. It keeps a pointer
to one of the blocks in the ring buffer (Starting at 0) and when the kernel
receives a packet it puts it in the buffer and updates the status with
at least the TP_STATUS_USER flag. Then the user can read the packet and
once the packet is read the user must reset the status fields to 
TP_STATUS_KERNEL, so the kernel can again use that frame buffer. The kernel fills a block, 
and it increments (modulo the number of block) the block pointer.

To check for new packets, the user can use the `poll()` function which takes in the
socket file descriptor (everything is a file in UNIX) and returns true when there are new
packets. Otherwise, the user could also use their own implementation to check for new
packets in the socket.


## References:

![https://www.kernel.org/doc/Documentation/networking/packet_mmap.txt](https://www.kernel.org/doc/Documentation/networking/packet_mmap.txt)
