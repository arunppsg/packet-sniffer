## Socket Options

` int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP))`

We use a socket of type AF_PACKET. The term AF_PACKET allows us to send or
 receive packets at layer 2 level. We analyse only IP Protocolsand hence we 
have set the protocol  level as `ETH_P_IP`. The SOCK_RAW keyword provides
access to raw network protocol.

### Packet Fanout

The application uses `PACKET_FANOUT_FLAG_ROLLOVER` as fanout configuration.
In this mode, if one socket is full, packets are rolled over to another group.
This helps in capture at high speed. Each thread of the application handles
a single socket and each socket is associated with a ring buffer. When one socket gets
full, this options helps in loading other sockets. It gets more time for the threads to
finish processing of packets in a thread.
