#include <iostream>
#include <cstring>
#include <cstdlib>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>

#define SERVER_PORT 12345  // Listening port

void print_tcp_flags(struct tcphdr *tcp) {
    std::cout << "[+] TCP Flags: "
              << " SYN: " << ((tcp->th_flags & TH_SYN) ? 1 : 0)
              << " ACK: " << ((tcp->th_flags & TH_ACK) ? 1 : 0)
              << " FIN: " << ((tcp->th_flags & TH_FIN) ? 1 : 0)
              << " RST: " << ((tcp->th_flags & TH_RST) ? 1 : 0)
              << " PSH: " << ((tcp->th_flags & TH_PUSH) ? 1 : 0)
              << " SEQ: " << ntohl(tcp->th_seq) << std::endl;
}

void send_syn_ack(int sock, struct sockaddr_in *client_addr, struct tcphdr *tcp) {
    char packet[sizeof(struct ip) + sizeof(struct tcphdr)];
    memset(packet, 0, sizeof(packet));

    struct ip *ip = (struct ip *)packet;
    struct tcphdr *tcp_response = (struct tcphdr *)(packet + sizeof(struct ip));

    // Fill IP header
    ip->ip_hl = 5;
    ip->ip_v = 4;
    ip->ip_tos = 0;
    ip->ip_len = htons(sizeof(packet));
    ip->ip_id = htons(54321);
    ip->ip_off = 0;
    ip->ip_ttl = 64;
    ip->ip_p = IPPROTO_TCP;
    ip->ip_src.s_addr = client_addr->sin_addr.s_addr;
    ip->ip_dst.s_addr = inet_addr("127.0.0.1");  // Server address

    // Fill TCP header
    tcp_response->th_sport = tcp->th_dport;
    tcp_response->th_dport = tcp->th_sport;
    tcp_response->th_seq = htonl(400);
    tcp_response->th_ack = htonl(ntohl(tcp->th_seq) + 1);
    tcp_response->th_off = 5;
    tcp_response->th_flags = TH_SYN | TH_ACK;
    tcp_response->th_win = htons(8192);
    tcp_response->th_sum = 0;  // Kernel will compute the checksum

    // Send packet
    if (sendto(sock, packet, sizeof(packet), 0, (struct sockaddr *)client_addr, sizeof(*client_addr)) < 0) {
        perror("sendto() failed");
    } else {
        std::cout << "[+] Sent SYN-ACK" << std::endl;
    }
}

void receive_syn() {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Enable IP header inclusion
    int one = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt() failed");
        exit(EXIT_FAILURE);
    }

    char buffer[65536];
    struct sockaddr_in source_addr;
    socklen_t addr_len = sizeof(source_addr);

    while (true) {
        int data_size = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&source_addr, &addr_len);
        if (data_size < 0) {
            perror("Packet reception failed");
            continue;
        }

        struct ip *ip = (struct ip *)buffer;
        struct tcphdr *tcp = (struct tcphdr *)(buffer + (ip->ip_hl * 4));

        // Only process packets for the correct destination port
        if (ntohs(tcp->th_dport) != SERVER_PORT) continue;

        print_tcp_flags(tcp);

        if ((tcp->th_flags & TH_SYN) && !(tcp->th_flags & TH_ACK) && ntohl(tcp->th_seq) == 200) {
            std::cout << "[+] Received SYN from " << inet_ntoa(source_addr.sin_addr) << std::endl;
            send_syn_ack(sock, &source_addr, tcp);
        }

        if ((tcp->th_flags & TH_ACK) && !(tcp->th_flags & TH_SYN) && ntohl(tcp->th_seq) == 600) {
            std::cout << "[+] Received ACK, handshake complete." << std::endl;
            break;
        }
    }

    close(sock);
}

int main() {
    std::cout << "[+] Server listening on port " << SERVER_PORT << "..." << std::endl;
    receive_syn();
    return 0;
}

