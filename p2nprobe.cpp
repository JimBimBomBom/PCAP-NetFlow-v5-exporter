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
#include <chrono>
#include <ctime>
#include <pcap.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>

// NetFlow v5 header structure
struct NetflowV5Header
{
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
struct NetflowV5Record
{
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

struct Flow
{
    uint8_t src_ip[4]; // Can hold IPv4
    uint8_t dst_ip[4];
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    uint8_t tcp_flags;
    uint32_t packet_count;
    uint32_t byte_count;
    struct timeval start_time;
    struct timeval last_time;
    uint8_t ip_version; // 4 for IPv4, 6 for IPv6
};

#define ETHERNET_IPV4_TYPE 0x0800

const size_t udp_max_size = 1500 - 20 - 8; // Ethernet MTU - IP Header - UDP Header
const size_t max_payload_size = udp_max_size;
const size_t netflow_header_size = sizeof(NetflowV5Header);
const size_t netflow_record_size = sizeof(NetflowV5Record);
const size_t max_records_per_packet = (max_payload_size - netflow_header_size) / netflow_record_size;

int extract_input_parameters(int argc, char *argv[], std::string &pcap_file_path, std::string &collector_address, int &collector_port, u_int32_t &active_timeout, u_int32_t &inactive_timeout)
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

        if (arg.find(':') != std::string::npos) // If argument contains a colon, it is a host:port pair
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
        else if (arg == "-i")
        {
            if (inactive_set)
            {
                std::cout << ("Error: Attempted to specify inactive_timeout multiple times.\n");
                success = 0;
                break;
            }
            inactive_set = 1;

            i += 1; // we are reading the next argument, so we have to skip this one
            auto inactive_value = atoi(argv[i]);
            if (inactive_value < 0)
            {
                std::cout << ("Error: Attempted to specify inactive_timeout with a negative value.\n");
                success = 0;
                break;
            }
            inactive_timeout = inactive_value;
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

            i += 1; // we are reading the next argument, so we have to skip this one
            auto active_value = atoi(argv[i]);
            if (active_value < 0)
            {
                std::cout << ("Error: Attempted to specify active_timeout with a negative value.\n");
                success = 0;
                break;
            }
            active_timeout = active_value;
        }
        else
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
    }

    if (!collector_set || !pcap_set)
    {
        std::cout << ("Error: Attempted to run the program without specifying the collector's host and port, or the pcap file path.\n");
        success = 0;
    }

    return success;
}

void process_packet(const u_char *packet, pcap_pkthdr *header, std::unordered_map<std::string, Flow> &active_flows)
{
    if (header->caplen < 14)
    {
        return; // Packet too short to contain Ethernet header
    }

    uint16_t ethernet_type = (packet[12] << 8) | packet[13];
    if (ethernet_type != ETHERNET_IPV4_TYPE)
    { // Ethernet packet does not contain an IPv4 packet
        return; // Ignore non-IPv4 packets
    }

    const u_char *ip_packet = packet + 14; // skip the Ethernet header
    uint8_t version = (*ip_packet) >> 4;
    if (version != 4)
    { // ensure that packet is IPv4 -> will only be other than 4 if ethernet packet is corrupted, since we already checked ethernet packet type to be IPv4
        return; // Ignore non-IPv4 packets
    }

    struct ip *ipv4_hdr = (struct ip *)ip_packet;
    if (ipv4_hdr->ip_p != IPPROTO_TCP)
    {
        return; // Ignore non-TCP packets
    }

    struct tcphdr *tcp_hdr = (struct tcphdr *)(ip_packet + (ipv4_hdr->ip_hl * 4));

    Flow flow;
    flow.packet_count = 1;
    u_int32_t layer3_bytes = header->len - 14;
    flow.byte_count = layer3_bytes;      // skip ethernet header
    flow.start_time = header->ts;
    flow.last_time = flow.start_time; // Use the same time for both start and last initially
    flow.ip_version = version;
    flow.tcp_flags = 0; // Initialize tcp_flags to 0
    flow.protocol = ipv4_hdr->ip_p;

    memcpy(flow.src_ip, &(ipv4_hdr->ip_src), 4);
    memcpy(flow.dst_ip, &(ipv4_hdr->ip_dst), 4);

    flow.src_port = ntohs(tcp_hdr->source);
    flow.dst_port = ntohs(tcp_hdr->dest);

    flow.tcp_flags = (tcp_hdr->fin << 0) |
                     (tcp_hdr->syn << 1) |
                     (tcp_hdr->rst << 2) |
                     (tcp_hdr->psh << 3) |
                     (tcp_hdr->ack << 4) |
                     (tcp_hdr->urg << 5);

    std::string flow_key = std::string(reinterpret_cast<char *>(flow.src_ip), 4) +
                           std::string(reinterpret_cast<char *>(flow.dst_ip), 4) +
                           std::to_string(flow.src_port) + "-" +
                           std::to_string(flow.dst_port) + "-" +
                           std::to_string(flow.protocol);

    auto it = active_flows.find(flow_key);
    if (it != active_flows.end())
    {
        Flow &existing_flow = it->second;

        // Update existing flow
        existing_flow.packet_count++;
        existing_flow.byte_count += flow.byte_count;
        existing_flow.last_time = header->ts;
        existing_flow.tcp_flags |= flow.tcp_flags;
    }
    else
    {
        // New flow, add it to active_flows
        active_flows[flow_key] = flow;
    }
}

u_int32_t timeval_diff(const struct timeval *t1, const struct timeval *t2)
{
    struct timeval result;

    result.tv_sec = t1->tv_sec - t2->tv_sec;
    result.tv_usec = t1->tv_usec - t2->tv_usec;
    if (result.tv_usec < 0)
    {
        result.tv_usec += 1000000;
        result.tv_sec--;
    }

    return ((u_int32_t)result.tv_sec * 1000 + (u_int32_t)result.tv_usec / 1000);
}

int send_netflow_v5_new(const std::vector<Flow> &flows, const std::string &collector_address, int collector_port, struct timeval sys_uptime, uint32_t &flow_sequence)
{
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
    {
        std::cerr << "Error creating socket" << std::endl;
        return -1;
    }

    struct addrinfo hints, *result;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    int status = getaddrinfo(collector_address.c_str(), std::to_string(collector_port).c_str(), &hints, &result);
    if (status != 0)
    {
        std::cerr << "getaddrinfo error: " << gai_strerror(status) << std::endl;
        close(sockfd);
        return -1;
    }

    const size_t packet_size = netflow_header_size + max_records_per_packet * netflow_record_size;
    std::vector<uint8_t> packet(packet_size); // allocate and initialize all fields to 0

    NetflowV5Header *header = reinterpret_cast<NetflowV5Header *>(packet.data());
    NetflowV5Record *records = reinterpret_cast<NetflowV5Record *>(packet.data() + sizeof(NetflowV5Header));

    size_t records_in_packet = std::min(max_records_per_packet, flows.size());

    // Fill header
    header->version = htons(5);
    header->count = htons(records_in_packet);
    struct timeval now;
    gettimeofday(&now, NULL);
    header->sys_uptime = htonl(timeval_diff(&now, &sys_uptime)); // time in miliseconds since exporter start
    header->unix_secs = htonl(now.tv_sec);
    header->unix_nsecs = htonl(now.tv_usec * 1000);
    header->flow_sequence = htonl(flow_sequence);

    // Fill records
    for (size_t j = 0; j < records_in_packet; ++j)
    {
        const Flow &flow = flows[j];
        NetflowV5Record &record = records[j];

        memcpy(&record.srcaddr, flow.src_ip, 4);
        memcpy(&record.dstaddr, flow.dst_ip, 4);

        record.srcaddr = record.srcaddr; // copied src_ip from packet -> already in network order
        record.dstaddr = record.dstaddr; // copied dst_ip from packet -> already in network order
        record.dPkts = htonl(flow.packet_count);
        record.dOctets = htonl(flow.byte_count);
        record.first = htonl(timeval_diff(&flow.start_time, &sys_uptime)); // time in miliseconds that the flow started compared to exporter start
        record.last = htonl(timeval_diff(&flow.last_time, &sys_uptime));   // time in miliseconds that the flow started compared to exporter start
        record.srcport = htons(flow.src_port);
        record.dstport = htons(flow.dst_port);
        record.tcp_flags = flow.tcp_flags;
        record.prot = flow.protocol;
    }

    // Send the packet
    size_t bytes_to_send = sizeof(NetflowV5Header) + records_in_packet * sizeof(NetflowV5Record);
    ssize_t bytes_sent = sendto(sockfd, packet.data(), bytes_to_send, 0, result->ai_addr, result->ai_addrlen);
    if (bytes_sent < 0)
    {
        std::cerr << "Error sending packet: " << strerror(errno) << std::endl;
        return -1;
    }

    flow_sequence += records_in_packet;

    freeaddrinfo(result);
    close(sockfd);

    return records_in_packet;
}

void remove_expired_flows(std::unordered_map<std::string, Flow> &active_flows, std::vector<Flow> &finished_flows, const struct timeval current_time, u_int32_t active_timeout, u_int32_t inactive_timeout)
{
    for (auto it = active_flows.begin(); it != active_flows.end();)
    {
        Flow &flow = it->second;
        bool timeout_violated = (timeval_diff(&current_time, &flow.start_time) > active_timeout) ||
                                (timeval_diff(&current_time, &flow.last_time) > inactive_timeout);

        if (timeout_violated)
        {
            finished_flows.push_back(flow);
            it = active_flows.erase(it);
        }
        else
        {
            ++it;
        }
    }
}

int convertPacketDataToFlows(std::string pcap_file_path, std::string collector_address, int collector_port, int active_timeout, int inactive_timeout)
{
    char errbuf[PCAP_ERRBUF_SIZE]; // Buffer to hold error messages

    pcap_t *pcap = pcap_open_offline(pcap_file_path.c_str(), errbuf);
    if (!pcap)
    {
        std::cerr << "Error opening pcap_file: " << errbuf << std::endl;
        return -1;
    }

    struct pcap_pkthdr *header; // Packet header
    const u_char *data;         // Packet data

    std::unordered_map<std::string, Flow> active_flows;
    std::vector<Flow> finished_flows;

    int returnValue;
    int packetCount = 0;
    active_timeout *= 1000;   // Convert to milliseconds
    inactive_timeout *= 1000; // Convert to milliseconds
    struct timeval now;       // Get the system uptime
    gettimeofday(&now, NULL);
    const struct timeval sys_uptime = now;
    uint32_t flow_sequence = 0;
    while ((returnValue = pcap_next_ex(pcap, &header, &data)) >= 0)
    {
        if (returnValue == 0)
        {
            continue;
        }

        remove_expired_flows(active_flows, finished_flows, header->ts, active_timeout, inactive_timeout); // moves expired flows from active to finished flows
        while (finished_flows.size() >= max_records_per_packet)
        {
            int records_sent = send_netflow_v5_new(finished_flows, collector_address, collector_port, sys_uptime, flow_sequence);
            if (records_sent == -1)
            {
                std::cerr << "Error sending flows to collector" << std::endl;
                return -1;
            }
            finished_flows.erase(finished_flows.begin(), finished_flows.begin() + records_sent); // sent records_sent flows, so remove them from finished_flows
        }

        process_packet(data, header, active_flows);
        packetCount++;
    }

    // After processing all packets, move any remaining active flows to finished_flows
    for (auto it = active_flows.begin(); it != active_flows.end(); ++it)
    {
        finished_flows.push_back(it->second);
    }

    while (finished_flows.size() > 0)
    {
        int records_sent = send_netflow_v5_new(finished_flows, collector_address, collector_port, sys_uptime, flow_sequence);
        finished_flows.erase(finished_flows.begin(), finished_flows.begin() + records_sent);
    }

    // Clean up
    pcap_close(pcap);
    return 0;
}

bool validate_address(const std::string &collector_address)
{
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, collector_address.c_str(), &(sa.sin_addr));
    return result == 1; // if inet_pton returns 1, the address is a valid IPv4 address
}

int main(int argc, char *argv[])
{
    std::string pcap_file_path = "";
    std::string collector_address = "";
    int collector_port = 0;
    u_int32_t active_timeout = 60;   // Default value
    u_int32_t inactive_timeout = 60; // Default value

    if (!extract_input_parameters(argc, argv, pcap_file_path, collector_address, collector_port, active_timeout, inactive_timeout))
    {
        return -1;
    }
    if (!validate_address(collector_address))
    {
        std::cerr << "Invalid collector address" << std::endl;
        return -1;
    }

    int result = convertPacketDataToFlows(pcap_file_path, collector_address, collector_port, active_timeout, inactive_timeout);

    return result;
}