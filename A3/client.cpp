#include <iostream>
#include <cstring>
#include <cstdlib>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <chrono>
#include <thread>

void print_tcp_flags(struct tcphdr *tcp) {
    std::cout << "[+] TCP Flags: "
              << " SYN: " << tcp->syn
              << " ACK: " << tcp->ack
              << " FIN: " << tcp->fin
              << " RST: " << tcp->rst
              << " PSH: " << tcp->psh
              << " SEQ: " << ntohl(tcp->seq)
              << " DST: " << ntohs(tcp->dest)
              << " SRC:  " << ntohs(tcp->source)  << std::endl;
}


int main() {
    // Create raw socket
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sockfd < 0) {
        perror("Socket creation failed");
        return 1;
    }

    // Enable IP header inclusion
    int one = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt() failed");
        return 1;
    }

    // Server setup
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(12345);
    server_addr.sin_addr.s_addr= inet_addr("127.0.0.1");  

    //local
    struct sockaddr_in local_addr;
    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(6969); // Use the client port
    local_addr.sin_addr.s_addr = inet_addr("127.0.0.1"); // Local IP

    // Build SYN packet
    char packet[sizeof(struct iphdr) + sizeof(struct tcphdr)];
    memset(packet, 0, sizeof(packet));

    struct iphdr *ip = (struct iphdr *)packet;
    struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct iphdr));

    // IP header
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->tot_len = htons(sizeof(packet));
    ip->id = htons(54321);
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_TCP;
    ip->saddr= local_addr.sin_addr.s_addr;
    ip->daddr = server_addr.sin_addr.s_addr;
    
    // TCP header (SYN)
    tcp->source = htons(6969);
    tcp->dest = htons(12345);
    tcp->seq = htonl(200);
    tcp->ack = 0;
    tcp->doff = 5;
    tcp->syn=1;
    tcp->window = htons(8192);
    tcp->check = 0;
    

    // Send SYN
    if (sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Sendto failed");
        close(sockfd);
        return 1;
    }

    std::cout << "[Client] SYN sent to 127.0.0.1:12345 \n";

    // Receive SYN-ACK
    

    //std::this_thread::sleep_for(std::chrono::seconds(3));
while(true){
    char recv_packet[65536];
    struct sockaddr_in from_addr;
    socklen_t from_len = sizeof(from_addr);
    int recv_size = recvfrom(sockfd, recv_packet, sizeof(recv_packet), 0, (struct sockaddr *)&from_addr, &from_len);
    if (recv_size < 0) {
        //std::cout<<"boom error HERE at 132 line"<<std::endl;
        perror("Recvfrom failed");
        close(sockfd);
        return 1;
    }

    struct iphdr *recv_ip = (struct iphdr *)recv_packet;
    struct tcphdr *recv_tcp = (struct tcphdr *)(recv_packet + (recv_ip->ihl * 4));
    
    
    // only reply from port 12345 should be 
    if( ntohs(recv_tcp->source) != 12345){    
        continue;
    }

    print_tcp_flags(recv_tcp);

    if ((recv_tcp->syn == 1 ) && (recv_tcp->ack == 1 ) && (ntohl(recv_tcp->ack_seq) == 201)) {
        std::cout << "[Client] SYN-ACK received.\n";       

        // Build ACK packet
        char ack_packet[sizeof(struct iphdr) + sizeof(struct tcphdr)];
        memset(ack_packet, 0, sizeof(ack_packet));

        struct iphdr *ack_ip = (struct iphdr *)ack_packet;
        struct tcphdr *ack_tcp = (struct tcphdr *)(ack_packet + sizeof(struct ip));

        memcpy(ack_ip, ip, sizeof(struct ip));
        //IP
        ack_ip->ihl=5;
        ack_ip->version = 4;
        ack_ip-> tos=0 ;
        ack_ip->tot_len =  htons(sizeof(ack_packet));
        ack_ip->frag_off = 0;
        ack_ip-> ttl= 64;
        ack_ip-> protocol = IPPROTO_TCP;
        ack_ip->id = htons(54321);
        ack_ip->saddr= local_addr.sin_addr.s_addr;
        ack_ip->daddr = server_addr.sin_addr.s_addr;
    
        //TCP
        ack_tcp->source = htons(6969);
        ack_tcp->dest = recv_tcp->source;
        ack_tcp->seq = htonl(ntohl(recv_tcp->seq)+200);
        ack_tcp->ack_seq = htonl(ntohl(recv_tcp->seq) + 1 );
        ack_tcp->ack = 1;
        ack_tcp->syn = 0;
        ack_tcp->doff = 5;
        ack_tcp->window = htons(8192);
        ack_tcp->check = 0;

        if (sendto(sockfd, ack_packet, sizeof(ack_packet), 0, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
            perror("Send to ACK failed");
            close(sockfd);
            return 1;
        }

        std::cout << "[Client] ACK sent. Handshake complete.\n";
        break;
    } 
    
    else {
        std::cerr << "[Client] Unexpected packet received.\n";
        break;
    }

}

    close(sockfd);
    return 0;
}
