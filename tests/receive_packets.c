#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>

int main(){
    int sockfd = socket(AF_INET, SOCK_RAW, ETH_P_IP);

}
