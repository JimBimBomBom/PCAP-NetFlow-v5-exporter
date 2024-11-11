#include <fstream>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <sstream>
#include <iterator>
#include <unordered_map>
#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <ctime>
#include <pcap.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>

// If TH_FIN and TH_RST are not defined in the system headers, define them here
#ifndef TH_FIN
#define TH_FIN 0x01
#endif

#ifndef TH_RST
#define TH_RST 0x04
#endif

int extract_input_parameters(int argc, char *argv[], std::string &pcap_file_path, std::string &collector_address, int &collector_port, int &active_timeout, int &inactive_timeout)
{
    int success = 1;
    if (argc <= 2 && argc >= 5)
    {
        std::cout << ("Invalid number of arguments.\n");
        return 0;
    }

    int pcap_set = 0, collector_set = 0, active_set = 0, inactive_set = 0;
    for (int i = 1; i < argc; i += 1)
    {
        std::string arg = argv[i];

        if (i == 1)
        {
            if (arg.find(':') != std::string::npos)
            {
                if (collector_set)
                {
                    std::cout << ("Error: Attempted to specify collector's host and port values multiple times.\n");
                    success = 0;
                    break;
                }
                collector_set = 1;

                size_t colon_pos = arg.find(':');
                collector_address = arg.substr(0, colon_pos);
                collector_port = std::stoi(arg.substr(colon_pos + 1));

                if (collector_port < 1 || collector_port > 65536)
                {
                    std::cout << ("Error: Attempted to specify collector's port to an invalid value. Port has to be in range <1, 65536>.\n");
                    success = 0;
                    break;
                }
            }
            else
            {
                std::cout << ("Error: Invalid value for collector address, specify IP/Domain:Port");
                success = 0;
                break;
            }
        }
        else if (i == 2)
        {
            if (pcap_set)
            {
                std::cout << ("Error: Attempted to specify pcap file path multiple times.\n");
                success = 0;
                break;
            }
            pcap_set = 1;
            // NOTE: maybe it would be nice to ensure that the file exists and can be read, before continuing

            pcap_file_path = argv[i];
        }
        else if (arg == "-i")
        {
            if (inactive_set)
            {
                std::cout << ("Error: Attempted to specify inactive_timeout multiple times.\n");
                success = 0;
                break;
            }
            inactive_set = 1;

            inactive_timeout = atoi(argv[i + 1]);
            i += 1; // we are reading the next argument, so we have to skip it next time
            if (inactive_timeout < 0)
            {
                std::cout << ("Error: Attempted to specify inactive_timeout with an incorrect value.\n");
                success = 0;
                break;
            }
        }
        else if (arg == "-a")
        {
            if (active_set)
            {
                std::cout << ("Error: Attempted to specify active_timeout multiple times.\n");
                success = 0;
                break;
            }
            active_set = 1;

            active_timeout = atoi(argv[i + 1]);
            i += 1; // we are reading the next argument, so we have to skip it next time
            if (active_timeout < 0)
            {
                std::cout << ("Error: Attempted to specify active_timeout with an incorrect value.\n");
                success = 0;
                break;
            }
        }
    }

    return success;
}

struct Flow
{
    uint8_t src_ip[16];  // Can hold both IPv4 and IPv6 addresses
    uint8_t dst_ip[16];
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    uint8_t tcp_flags;
    uint32_t packet_count;
    uint32_t byte_count;
    uint64_t start_time;
    uint64_t last_time;
    uint8_t ip_version;  // 4 for IPv4, 6 for IPv6

    // Updated print function
    void print() const {
        char src_ip_str[INET6_ADDRSTRLEN];
        char dst_ip_str[INET6_ADDRSTRLEN];

        if (ip_version == 4) {
            inet_ntop(AF_INET, src_ip, src_ip_str, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET, dst_ip, dst_ip_str, INET6_ADDRSTRLEN);
        } else {
            inet_ntop(AF_INET6, src_ip, src_ip_str, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, dst_ip, dst_ip_str, INET6_ADDRSTRLEN);
        }

        std::cout << "Flow Information:" << std::endl;
        std::cout << "  IP Version: " << (int)ip_version << std::endl;
        std::cout << "  Source IP: " << src_ip_str << std::endl;
        std::cout << "  Destination IP: " << dst_ip_str << std::endl;
        std::cout << "  Source Port: " << src_port << std::endl;
        std::cout << "  Destination Port: " << dst_port << std::endl;
        std::cout << "  Protocol: " << (int)protocol << std::endl;
        std::cout << "  Packet Count: " << packet_count << std::endl;
        std::cout << "  Byte Count: " << byte_count << std::endl;
        std::cout << "  Start Time: " << start_time << " ms" << std::endl;
        std::cout << "  Last Time: " << last_time << " ms" << std::endl;
        
        // New graphical TCP flags output
        std::cout << "  TCP Flags: ";
        bool first_flag = true;
        if (tcp_flags & 0x01) { std::cout << (first_flag ? "" : ", ") << "FIN"; first_flag = false; }
        if (tcp_flags & 0x02) { std::cout << (first_flag ? "" : ", ") << "SYN"; first_flag = false; }
        if (tcp_flags & 0x04) { std::cout << (first_flag ? "" : ", ") << "RST"; first_flag = false; }
        if (tcp_flags & 0x08) { std::cout << (first_flag ? "" : ", ") << "PSH"; first_flag = false; }
        if (tcp_flags & 0x10) { std::cout << (first_flag ? "" : ", ") << "ACK"; first_flag = false; }
        if (tcp_flags & 0x20) { std::cout << (first_flag ? "" : ", ") << "URG"; first_flag = false; }
        if (first_flag) { std::cout << "None"; }
        std::cout << std::endl;
    }
};

#define ETHERNET_IPV4_TYPE 0x0800
#define ETHERNET_IPV6_TYPE 0x86DD

int nonIpPackets = 0;
int nonIp4Packets = 0;
int nonTcpPackets = 0;
// Updated process_packet function
void process_packet(const u_char* packet, pcap_pkthdr *header, std::unordered_map<std::string, Flow>& active_flows, std::vector<Flow>& finished_flows, int active_timeout, int inactive_timeout) {
    if (header->caplen < 14) {
        nonIpPackets++;
        return;  // Packet too short to contain Ethernet header
    }

    uint16_t ethernet_type = (packet[12] << 8) | packet[13];
    if (ethernet_type != ETHERNET_IPV4_TYPE && ethernet_type != ETHERNET_IPV6_TYPE) {
        nonIpPackets++;
        return;  // Ignore non-IP packets
    }

    const u_char* ip_packet = packet + 14;  // Default: skip the Ethernet header
    uint8_t version = (*ip_packet) >> 4;
    if (version != 4) {
        nonIp4Packets++;
        return;  // Ignore non-IPv4 packets
    }

    struct ip* ipv4_hdr = (struct ip*)ip_packet;
    if (ipv4_hdr->ip_p != IPPROTO_TCP) {
        nonTcpPackets++;
        return;  // Ignore non-TCP packets
    }

    Flow flow;
    flow.packet_count = 1;
    flow.byte_count = header->len;
    flow.start_time = header->ts.tv_sec * 1000 + header->ts.tv_usec / 1000; // Convert to milliseconds
    flow.last_time = flow.start_time; // Use the same time for both start and last initially
    flow.ip_version = version;
    flow.tcp_flags = 0;  // Initialize tcp_flags to 0
    flow.protocol = ipv4_hdr->ip_p;

    memcpy(flow.src_ip, &(ipv4_hdr->ip_src), 4);
    memcpy(flow.dst_ip, &(ipv4_hdr->ip_dst), 4);
    memset(flow.src_ip + 4, 0, 12);  // Zero-pad the remaining bytes
    memset(flow.dst_ip + 4, 0, 12);

    struct tcphdr* tcp_hdr = (struct tcphdr*)(ip_packet + (ipv4_hdr->ip_hl * 4));
    flow.src_port = ntohs(tcp_hdr->source);
    flow.dst_port = ntohs(tcp_hdr->dest);
    
    flow.tcp_flags = (tcp_hdr->fin << 0) |
                        (tcp_hdr->syn << 1) |
                        (tcp_hdr->rst << 2) |
                        (tcp_hdr->psh << 3) |
                        (tcp_hdr->ack << 4) |
                        (tcp_hdr->urg << 5);

    std::string flow_key = std::string(reinterpret_cast<char*>(flow.src_ip), 16) +
                           std::string(reinterpret_cast<char*>(flow.dst_ip), 16) +
                           std::to_string(flow.src_port) + "-" +
                           std::to_string(flow.dst_port) + "-" +
                           std::to_string(flow.protocol);

    auto it = active_flows.find(flow_key);
    if (it != active_flows.end()) {
        Flow& existing_flow = it->second;
        uint64_t current_time = header->ts.tv_sec * 1000 + header->ts.tv_usec / 1000; // Convert to milliseconds

        bool timeout_violated = (current_time - existing_flow.start_time > active_timeout * 1000) ||
                                (current_time - existing_flow.last_time > inactive_timeout * 1000);

        if (timeout_violated) {
            // Timeout violated: finish the existing flow without including this packet
            finished_flows.push_back(existing_flow);
            active_flows.erase(it);

            // Start a new flow with this packet
            flow.start_time = current_time;
            flow.last_time = current_time;
            active_flows[flow_key] = flow;
        } else {
            // Update existing flow
            existing_flow.packet_count++;
            existing_flow.byte_count += flow.byte_count;
            existing_flow.last_time = current_time;
            existing_flow.tcp_flags |= flow.tcp_flags;
        }
    } else {
        // New flow, add it to active_flows
        active_flows[flow_key] = flow;
    }
}

// NetFlow v5 header structure
struct NetflowV5Header {
    uint16_t version;
    uint16_t count;
    uint32_t sys_uptime;
    uint32_t unix_secs;
    uint32_t unix_nsecs;
    uint32_t flow_sequence;
    uint8_t engine_type;
    uint8_t engine_id;
    uint16_t sampling_interval;
};

// Updated NetFlow v5 record structure
struct NetflowV5Record {
    uint32_t srcaddr;
    uint32_t dstaddr;
    uint32_t nexthop;
    uint16_t input;
    uint16_t output;
    uint32_t dPkts;
    uint32_t dOctets;
    uint32_t first;
    uint32_t last;
    uint16_t srcport;
    uint16_t dstport;
    uint8_t pad1;
    uint8_t tcp_flags;
    uint8_t prot;
    uint8_t tos;
    uint16_t src_as;
    uint16_t dst_as;
    uint8_t src_mask;
    uint8_t dst_mask;
    uint16_t pad2;
};

// Function to send NetFlow v5 data-flows
void send_netflow_v5(const std::vector<Flow>& flows, const std::string& collector_address, int collector_port) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        std::cerr << "Error creating socket" << std::endl;
        return;
    }

    struct addrinfo hints, *result;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    int status = getaddrinfo(collector_address.c_str(), std::to_string(collector_port).c_str(), &hints, &result);
    if (status != 0) {
        std::cerr << "getaddrinfo error: " << gai_strerror(status) << std::endl;
        close(sockfd);
        return;
    }

    const size_t udp_max_size = 1500 - 20 - 8; // Ethernet MTU - IP Header - UDP Header
    const size_t max_payload_size = udp_max_size;

    const size_t netflow_header_size = sizeof(NetflowV5Header);
    const size_t netflow_record_size = sizeof(NetflowV5Record);

    // Calculate the maximum number of records that can fit in a packet
    const size_t max_records_per_packet = (max_payload_size - netflow_header_size) / netflow_record_size;

    const size_t packet_size = netflow_header_size + max_records_per_packet * netflow_record_size;
    std::vector<uint8_t> packet(packet_size);

    // std::cout << "Netflow header size: " << netflow_header_size << " bytes" << std::endl;
    // std::cout << "Netflow record size: " << netflow_record_size << " bytes" << std::endl;
    // std::cout << "Max records per packet: " << max_records_per_packet << std::endl;
    // std::cout << "Packet size: " << packet_size << " bytes" << std::endl;

    std::cout << "Sending " << flows.size() << " to collector in " << flows.size() / max_records_per_packet + 1 << " packets" << std::endl;

    NetflowV5Header* header = reinterpret_cast<NetflowV5Header*>(packet.data());
    NetflowV5Record* records = reinterpret_cast<NetflowV5Record*>(packet.data() + sizeof(NetflowV5Header));

    uint32_t flow_sequence = 0;
    uint32_t sys_uptime = 0; // You may want to implement a proper uptime

    for (size_t i = 0; i < flows.size(); i += max_records_per_packet) {
        size_t records_in_packet = std::min(max_records_per_packet, flows.size() - i);

        // Fill header
        header->version = htons(5);
        header->count = htons(records_in_packet);
        header->sys_uptime = htonl(sys_uptime);

        header->unix_secs = 0;
        header->unix_nsecs = 0;

        header->flow_sequence = htonl(flow_sequence);
        header->engine_type = 0;
        header->engine_id = 0;
        header->sampling_interval = 0;

        // Fill records
        for (size_t j = 0; j < records_in_packet; ++j) {
            const Flow& flow = flows[i + j];
            NetflowV5Record& record = records[j];

            memset(&record, 0, sizeof(record)); // Initialize all fields to 0

            if (flow.ip_version == 4) {
                memcpy(&record.srcaddr, flow.src_ip, 4);
                memcpy(&record.dstaddr, flow.dst_ip, 4);
            } else {
                // For IPv6, we'll just use the first 4 bytes of the address
                memcpy(&record.srcaddr, flow.src_ip, 4);
                memcpy(&record.dstaddr, flow.dst_ip, 4);
            }

            record.srcaddr = ntohl(record.srcaddr);
            record.dstaddr = ntohl(record.dstaddr);
            record.dPkts = htonl(flow.packet_count);
            record.dOctets = htonl(flow.byte_count);
            record.first = htonl(flow.start_time);
            record.last = htonl(flow.last_time);
            record.srcport = htons(flow.src_port);
            record.dstport = htons(flow.dst_port);
            record.tcp_flags = flow.tcp_flags;
            record.prot = flow.protocol;
        }

        // Send the packet
        size_t bytes_to_send = sizeof(NetflowV5Header) + records_in_packet * sizeof(NetflowV5Record);
        ssize_t bytes_sent = sendto(sockfd, packet.data(), bytes_to_send, 0, result->ai_addr, result->ai_addrlen);
        if (bytes_sent < 0) {
            std::cerr << "Error sending packet: " << strerror(errno) << std::endl;
        }

        flow_sequence += records_in_packet;
    }

    freeaddrinfo(result);
    close(sockfd);
}

int convertPacketDataToFlows(std::string pcap_file_path, std::string collector_address, int collector_port, int active_timeout, int inactive_timeout)
{
    char errbuf[PCAP_ERRBUF_SIZE];  // Buffer to hold error messages

    pcap_t* pcap = pcap_open_offline(pcap_file_path.c_str(), errbuf);
    if (!pcap) 
    {
        std::cerr << "Error opening file: " << errbuf << std::endl;
        return 1;
    }

    struct pcap_pkthdr* header;  // Packet header
    const u_char* data;          // Packet data

    std::unordered_map<std::string, Flow> active_flows;
    std::vector<Flow> finished_flows;

    int returnValue;
    int packetCount = 0;
    while ((returnValue = pcap_next_ex(pcap, &header, &data)) >= 0) 
    {
        if (returnValue == 0) 
        {
            continue;
        }

        process_packet(data, header, active_flows, finished_flows, active_timeout, inactive_timeout);
        packetCount++;
    }

    // After processing all packets, move any remaining active flows to finished_flows
    std::cout << "Number of active flows at exit: " << active_flows.size() << std::endl;
    std::cout << "Number of finished flows at exit: " << finished_flows.size() << std::endl;
    for (const auto& pair : active_flows) {
        finished_flows.push_back(pair.second);
    }

    // std::cout << "Number of packets processed: " << packetCount << std::endl;
    // std::cout << "Number of non-IP packets: " << nonIpPackets << std::endl;
    // std::cout << "Number of non-TCP packets: " << nonTcpPackets << std::endl;
    // std::cout << "Number of TCP packets: " << packetCount - nonIpPackets - nonTcpPackets << std::endl;
    std::cout << "Number of finished flows: " << finished_flows.size() << std::endl;

    // Send NetFlow v5 packets
    send_netflow_v5(finished_flows, collector_address, collector_port);

    // Clean up
    pcap_close(pcap);
    return 0;
}

int main(int argc, char *argv[])
{
    std::string pcap_file_path = "";
    std::string collector_address = "";
    int collector_port = 0;
    int active_timeout = 60;   // Default value
    int inactive_timeout = 60; // Default value

    if (!extract_input_parameters(argc, argv, pcap_file_path, collector_address, collector_port, active_timeout, inactive_timeout))
    {
        std::cout << ("Error during initialization. The problem could lie with a required init command-line argument missing, or being incorrectly formatted. Double check the service launch process.\n");
        return 1;
    }

    // NOTE: is it useful for this function to have a return value?
    int result = convertPacketDataToFlows(pcap_file_path, collector_address, collector_port, active_timeout, inactive_timeout);

    return 1;
}