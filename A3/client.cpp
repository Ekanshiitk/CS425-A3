#include <iostream>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>

// Pseudo-header used for TCP checksum calculation
struct pseudo_header {
    u_int32_t source_addr;
    u_int32_t dest_addr;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};

// Compute checksum (IP or TCP)
unsigned short compute_checksum(unsigned short *addr, unsigned int len) {
    unsigned long sum = 0;
    while (len > 1) {
        sum += *addr++;
        len -= 2;
    }
    if (len == 1) {
        sum += *(unsigned char *)addr;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

int main() {
    // Create raw socket
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sockfd < 0) {
        perror("Socket creation failed");
        return 1;
    }

    // Enable IP_HDRINCL
    int one = 1;
    const int *val = &one;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
        perror("setsockopt() failed");
        return 1;
    }

    // Server setup
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(12345);  // Server's hardcoded port
    inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr); // Server's hardcoded IP

    // Local client config
    const char *client_ip = "127.0.0.1";
    unsigned short client_port = 54321; // Arbitrary client port

    // Build SYN packet
    char packet[sizeof(struct ip) + sizeof(struct tcphdr)];
    memset(packet, 0, sizeof(packet));

    struct ip *ip = (struct ip *)packet;
    struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct ip));

    // IP header
    ip->ip_v = 4;
    ip->ip_hl = 5;
    ip->ip_tos = 0;
    ip->ip_len = htons(sizeof(packet));
    ip->ip_id = htons(54321);
    ip->ip_off = 0;
    ip->ip_ttl = 64;
    ip->ip_p = IPPROTO_TCP;
    inet_pton(AF_INET, client_ip, &ip->ip_src.s_addr);
    ip->ip_dst.s_addr = server_addr.sin_addr.s_addr;
    ip->ip_sum = compute_checksum((unsigned short *)ip, sizeof(struct ip));

    // TCP header (SYN)
    tcp->th_sport = htons(client_port);
    tcp->th_dport = htons(12345);
    tcp->th_seq = htonl(1234);
    tcp->th_ack = 0;
    tcp->th_off = 5;
    tcp->th_flags = TH_SYN;
    tcp->th_win = htons(64240);
    tcp->th_urp = 0;

    // TCP checksum
    pseudo_header psh;
    psh.source_addr = ip->ip_src.s_addr;
    psh.dest_addr = ip->ip_dst.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr));

    char pseudo_packet[sizeof(psh) + sizeof(struct tcphdr)];
    memcpy(pseudo_packet, &psh, sizeof(psh));
    memcpy(pseudo_packet + sizeof(psh), tcp, sizeof(struct tcphdr));
    tcp->th_sum = compute_checksum((unsigned short *)pseudo_packet, sizeof(pseudo_packet));

    // Send SYN
    if (sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Sendto failed");
        close(sockfd);
        return 1;
    }

    std::cout << "[Client] SYN sent to 127.0.0.1:12345\n";

    // Receive SYN-ACK
    char recv_packet[1024];
    struct sockaddr_in from_addr;
    socklen_t from_len = sizeof(from_addr);

    ssize_t recv_size = recvfrom(sockfd, recv_packet, sizeof(recv_packet), 0, (struct sockaddr *)&from_addr, &from_len);
    if (recv_size < 0) {
        perror("Recvfrom failed");
        close(sockfd);
        return 1;
    }

    struct ip *recv_ip = (struct ip *)recv_packet;
    struct tcphdr *recv_tcp = (struct tcphdr *)(recv_packet + (recv_ip->ip_hl * 4));

    if ((recv_tcp->th_flags & TH_SYN) && (recv_tcp->th_flags & TH_ACK)) {
        std::cout << "[Client] SYN-ACK received.\n";

        uint32_t server_seq = ntohl(recv_tcp->th_seq);
        uint32_t ack_num = ntohl(recv_tcp->th_ack);

        // Build ACK packet
        char ack_packet[sizeof(struct ip) + sizeof(struct tcphdr)];
        memset(ack_packet, 0, sizeof(ack_packet));

        struct ip *ack_ip = (struct ip *)ack_packet;
        struct tcphdr *ack_tcp = (struct tcphdr *)(ack_packet + sizeof(struct ip));

        memcpy(ack_ip, ip, sizeof(struct ip));
        ack_ip->ip_id = htons(54322);
        ack_ip->ip_sum = 0;
        ack_ip->ip_sum = compute_checksum((unsigned short *)ack_ip, sizeof(struct ip));

        ack_tcp->th_sport = htons(client_port);
        ack_tcp->th_dport = htons(12345);
        ack_tcp->th_seq = htonl(ack_num);
        ack_tcp->th_ack = htonl(server_seq + 1);
        ack_tcp->th_off = 5;
        ack_tcp->th_flags = TH_ACK;
        ack_tcp->th_win = htons(64240);
        ack_tcp->th_urp = 0;

        pseudo_header ack_psh;
        ack_psh.source_addr = ack_ip->ip_src.s_addr;
        ack_psh.dest_addr = ack_ip->ip_dst.s_addr;
        ack_psh.placeholder = 0;
        ack_psh.protocol = IPPROTO_TCP;
        ack_psh.tcp_length = htons(sizeof(struct tcphdr));

        char ack_pseudo[sizeof(ack_psh) + sizeof(struct tcphdr)];
        memcpy(ack_pseudo, &ack_psh, sizeof(ack_psh));
        memcpy(ack_pseudo + sizeof(ack_psh), ack_tcp, sizeof(struct tcphdr));
        ack_tcp->th_sum = compute_checksum((unsigned short *)ack_pseudo, sizeof(ack_pseudo));

        if (sendto(sockfd, ack_packet, sizeof(ack_packet), 0, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
            perror("Send to ACK failed");
            close(sockfd);
            return 1;
        }

        std::cout << "[Client] ACK sent. Handshake complete.\n";
    } else {
        std::cerr << "[Client] Unexpected packet received.\n";
    }

    close(sockfd);
    return 0;
}
