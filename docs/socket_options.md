
` int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));`

We use a socket of type AF_PACKET. The term AF_PACKET allows us to send or
 receive packets at layer 2 level. We analyse only IP Protocolsand hence we 
have set the protocol  level as `ETH_P_IP`. The SOCK_RAW keyword provides
access to raw network protocol.

PACKET_FANOUT

We use Packet_fanout_lb for load balancing of traffic across
all sockets.
