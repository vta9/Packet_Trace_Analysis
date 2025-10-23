/* 
Vincent Ave'Lallemant
vta9
proj3.cpp
10/18/2025
Code to print packet header, net flow, and rtt info from a packet trace file 
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <net/ethernet.h> 
#include <netinet/ip.h> 
#include <netinet/udp.h> 
#include <netinet/tcp.h> 
#include <unordered_map>
#include <vector>
#include <algorithm>

#define ARG_PACKET_PRINT 0x1
#define ARG_NET_FLOW 0x2
#define ARG_RTT 0x4
#define ARG_TRACE_FILE 0x8

#define DNE -1
#define MIN_PKT_SIZE 22
#define IPV4_TYPE 0x0800
#define IPV4_HDR_SIZE 20
#define UDP_PROTOCOL 17
#define TCP_PROTOCOL 6
#define UDP_HDR_SIZE 8
#define TCP_MIN_SIZE 20
#define DOFF_OFFSET 4
#define IPv4_SIZE 4
#define BYTE_SIZE 8
#define MASK 0xFF
#define U_SEC_CONV_FACTOR 1000000.0
#define TH_ACK 0x10


unsigned short cmd_line_flags = 0;
char* trace_file_name = NULL;

//Type all output functions 
typedef void (*Out_Function)(FILE*);

//Defines a Packet from trace file 
struct Packet{
    //Garunteed to exist 
    uint32_t sec_net;
    uint32_t usec_net; 
    struct ether_header ethernet_hdr;

    //May or may not point to real headers
    struct iphdr *ip_hdr;
    struct udphdr *udp_hdr;
    struct tcphdr *tcp_hdr;

};

//A packet that has fields in network byte order and more accessible fields 
struct ParsedPacket{
    uint32_t sec_net;
    uint32_t usec_net; 

    uint32_t sip;
    uint32_t dip;
    uint16_t sport;
    uint16_t dport;
    char protocol;

    u_int transport_hdr_size;
    uint16_t tot_len;
    uint32_t paylen;

    uint32_t seq;
    uint32_t ack;

    uint8_t th_flags;

    ParsedPacket(Packet& pkt) {
        this->sec_net = ntohl(pkt.sec_net);
        this->usec_net = ntohl(pkt.usec_net);
        this->sip = ntohl(pkt.ip_hdr->saddr);
        this->dip = ntohl(pkt.ip_hdr->daddr);
        this->tot_len = ntohs(pkt.ip_hdr->tot_len);

        if (pkt.ip_hdr->protocol == UDP_PROTOCOL) {
            this->sport = ntohs(pkt.udp_hdr->uh_sport);
            this->dport = ntohs(pkt.udp_hdr->uh_dport);
            this->protocol = 'U';
            this->transport_hdr_size = UDP_HDR_SIZE;
            this->paylen = this->tot_len - IPV4_HDR_SIZE - this->transport_hdr_size;

        }
        else {
            this->sport = ntohs(pkt.tcp_hdr->th_sport);
            this->dport = ntohs(pkt.tcp_hdr->th_dport);
            this->protocol = 'T';
            this->transport_hdr_size = (DOFF_OFFSET*pkt.tcp_hdr->th_off);
            this->paylen = this->tot_len - IPV4_HDR_SIZE - this->transport_hdr_size;
            this->seq =  ntohl(pkt.tcp_hdr->seq);
            this->ack = ntohl(pkt.tcp_hdr->th_ack);
            this->th_flags = pkt.tcp_hdr->th_flags;
        }

    }


};

//Defines a 5 tuple flow to be used as key in hash table
struct NF_Flow {
    uint32_t sip;
    uint32_t dip;
    uint16_t sport;
    uint16_t dport;
    char protocol;


    NF_Flow(const ParsedPacket pkt) {
        this->sip = pkt.sip;
        this-> dip = pkt.dip;
        this->sport = pkt.sport;
        this->dport = pkt.dport;
        this->protocol = pkt.protocol;
    }

    NF_Flow(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport,char protocol) {
        this->sip = sip;
        this-> dip = dip;
        this->sport = sport;
        this->dport = dport;
        this->protocol = protocol;
    }

    bool operator==(const NF_Flow &other) const { 
        return (sip == other.sip
            && dip == other.dip
            && sport == other.sport
            && dport == other.dport
            && protocol == other.protocol);
    }
};

//Defines a custom hash function for the NF hash table 
struct NF_Hasher {
    size_t operator()(const NF_Flow& nf_flw) const {
        //not using xor to hash because the order matters 
        std::string key = std::to_string(nf_flw.sip) + "-" +
            std::to_string(nf_flw.sport) + "-" +
            std::to_string(nf_flw.dip) + "-" +
            std::to_string(nf_flw.dport) + "-" +
            std::to_string(nf_flw.protocol);
        return std::hash<std::string>{}(key);
    }
};

//Defines a value of NF entry in hash table
struct NF_Flow_Info {
    uint32_t first_tv_sec;
    uint32_t first_tv_usec;
    uint32_t final_tv_sec;
    uint32_t final_tv_usec;
    uint tot_pkts;
    uint tot_payload_bytes;

    //specific to rtt mode
    uint32_t first_seq;
    uint32_t first_seq_tv_sec = UINT32_MAX;
    uint32_t first_seq_tv_usec  = UINT32_MAX;
    std::vector<std::pair<uint32_t, std::pair<uint32_t, uint32_t>>> ack_timestamps;


    NF_Flow_Info() {
        first_tv_sec = 0;
        first_tv_usec = 0;
        final_tv_sec = 0;
        final_tv_usec = 0;
        tot_pkts = 0;
        tot_payload_bytes = 0;
    }

    NF_Flow_Info(uint32_t first_tv_sec, uint32_t first_tv_usec, uint32_t final_tv_sec, uint32_t final_tv_usec, uint tot_pkts, uint tot_payload_bytes) {
        this->first_tv_sec = first_tv_sec;
        this->first_tv_usec = first_tv_usec;
        this->final_tv_sec = final_tv_sec;
        this->final_tv_usec = final_tv_usec;
        this->tot_pkts = tot_pkts;
        this->tot_payload_bytes = tot_payload_bytes;
    }

    void update_seq(ParsedPacket pkt) {
        this->first_seq = pkt.seq;
        this->first_seq_tv_sec = pkt.sec_net;
        this->first_seq_tv_usec = pkt.usec_net;
    }

};

//Adds arg to cmd_line_flags unless it was already given 
void set_arg(unsigned short arg, char option) {
    if (cmd_line_flags & arg) {
        fprintf(stderr, "error: option -%c given more than once\n", option);
        exit(1);
    } 
    cmd_line_flags |= arg;
}

//Obtains arguments from cmd line
void parseargs (int argc, char* argv []) {
    int opt;
    opterr = 0;

    while ((opt = getopt (argc, argv, "pnrf:")) != DNE) {
        switch (opt){
            case 'p':
                set_arg(ARG_PACKET_PRINT, 'p');
                break;
            case 'n':
                set_arg(ARG_NET_FLOW, 'n');
                break;
            case 'r':
                set_arg(ARG_RTT, 'r');
                break;
            case 'f':
                set_arg(ARG_TRACE_FILE, 'f');
                trace_file_name = optarg;
                break;
            case '?':
                if (optopt == 'f') {
                    fprintf(stderr, "error: [-f] without file name given\n");
                    exit(1);
                }
                else {
                    fprintf(stderr, "error: unknown option given: -%c\n", optopt);
                    exit(1);
                }
        }
    }
    if (cmd_line_flags == 0) {
        fprintf (stderr,"error: no command line option given\n");
        exit(1);
    }
}

void validate_arguments() {
    //check that tracefile was given
    if((cmd_line_flags & ARG_TRACE_FILE) != ARG_TRACE_FILE || trace_file_name == NULL) {
        fprintf(stderr, "error: no trace file given\n");
        exit(1);
    }
    //check that only one mode is given
    int modes = cmd_line_flags & (ARG_RTT | ARG_PACKET_PRINT | ARG_NET_FLOW);
    if (modes == (ARG_RTT | ARG_PACKET_PRINT | ARG_NET_FLOW) || 
        modes == (ARG_RTT | ARG_PACKET_PRINT) ||
        modes == (ARG_RTT | ARG_NET_FLOW) ||
        modes == (ARG_PACKET_PRINT | ARG_NET_FLOW)) 
    {
        fprintf(stderr, "error: cannot give multiple mode options\n");
        exit(1);
    }

}

//Opens file and checks for file dne 
FILE *open_file(const char* file_name) {
    FILE* fptr;
    fptr = fopen(file_name, "rb");
    if (fptr == NULL) {
        fprintf(stderr, "error: cannot open file: %s\n", file_name);
        exit(1);
    }
    return fptr;
}

//Wrapper function for output functoins 
void run_w_file(Out_Function func, const char* file_name) {
    FILE* fptr = open_file(file_name);
    func(fptr);
    fclose(fptr);
}


//Returns a vector of the packets in the trace file
std::vector<ParsedPacket> get_packets(FILE* fptr) {
    std::vector<ParsedPacket> packets;
    struct Packet pkt;

    pkt.ip_hdr = nullptr;
    pkt.udp_hdr = nullptr;
    pkt.tcp_hdr = nullptr;


    while(fread(&pkt, 1, MIN_PKT_SIZE, fptr) == MIN_PKT_SIZE) {
        bool ignore = false;
        if (ntohs(pkt.ethernet_hdr.ether_type) == IPV4_TYPE) {
            //malloc for iphdr pointer 
            pkt.ip_hdr = (struct iphdr *) malloc(IPV4_HDR_SIZE);
            //check if malloc worked                                //holy repeated code
            if (pkt.ip_hdr == nullptr) {
                fprintf(stderr, "error: allocation failed\n");
                exit(1);
            }

            //next 20 bytes garunteed to be ipv4 header 
            fread(pkt.ip_hdr, 1, IPV4_HDR_SIZE, fptr);
            //now check if protocol is udp or tcp 
            //just 8 bits so dont need to ntohs 
            if (pkt.ip_hdr->protocol == UDP_PROTOCOL) {

                //malloc for udp hdr pointer 
                pkt.udp_hdr = (struct udphdr *) malloc(UDP_HDR_SIZE);
                //check if malloc worked 
                if (pkt.udp_hdr == nullptr) {
                    fprintf(stderr, "error: allocation failed\n");
                    exit(1);
                }

                if (fread(pkt.udp_hdr, 1, UDP_HDR_SIZE, fptr) != UDP_HDR_SIZE ) {
                    fprintf(stderr, "error: unexpected EOF reading UDP header\n");
                    free(pkt.ip_hdr); pkt.ip_hdr = nullptr;
                    break;
                }
            }
            else if (pkt.ip_hdr->protocol == TCP_PROTOCOL) {

                //malloc for tcp hdr pointer 
                pkt.tcp_hdr = (struct tcphdr *) malloc(TCP_MIN_SIZE);
                //check if malloc worked 
                if (pkt.tcp_hdr == nullptr) {
                    fprintf(stderr, "error: allocation failed\n");
                    exit(1);
                }

                if (fread(pkt.tcp_hdr, 1, TCP_MIN_SIZE, fptr) != TCP_MIN_SIZE) {
                    fprintf(stderr, "error: unexpected EOF reading TCP base header\n");
                    free(pkt.ip_hdr); pkt.ip_hdr = nullptr;
                    break;
                }

                //multiply offset by 4 to get total length of header 
                //continue reading total length - 20 bytes of header
                int rem_length = (pkt.tcp_hdr->th_off * DOFF_OFFSET) - TCP_MIN_SIZE;

                if (rem_length > 0) {
                    //realloc to increase length
                    //malloc for tcp hdr pointer 
                    pkt.tcp_hdr = (struct tcphdr *) realloc(pkt.tcp_hdr, TCP_MIN_SIZE + rem_length);
                    //check if malloc worked 
                    if (pkt.tcp_hdr == nullptr) {
                        fprintf(stderr, "error: allocation failed\n");
                        exit(1);
                    }
                    
                    //kms kms kms 
                    u_int8_t* end_of_tcp = (u_int8_t*) (pkt.tcp_hdr) + TCP_MIN_SIZE;
                    if (fread(end_of_tcp, 1, rem_length, fptr) != rem_length) {
                        fprintf(stderr, "error: unexpected EOF reading TCP remaining header\n");
                        free(pkt.ip_hdr); pkt.ip_hdr = nullptr;
                        break;
                    }
                }
            }
            else {
                ignore = true;
            } 
        }
        else {
            ignore = true;
        }
        if (!ignore) {
            ParsedPacket parsed_pkt(pkt);
            packets.push_back(parsed_pkt);
        }

        //Regardless of if we push packet to stack, need to free everything
        if (pkt.ip_hdr) { 
            free(pkt.ip_hdr); 
            pkt.ip_hdr = nullptr; 
        }
        if (pkt.udp_hdr) { 
            free(pkt.udp_hdr); 
            pkt.udp_hdr = nullptr; 
        }
        if (pkt.tcp_hdr) { 
            free(pkt.tcp_hdr); 
            pkt.tcp_hdr = nullptr; 
        }
    }
    return packets;
}

//Prints ipaddr in dotted quad with a space at the end
void print_ip(uint32_t ipaddr) {
    for (int i = IPv4_SIZE - 1; i >= 0; i--) {
        fprintf(stdout, "%u", ((ipaddr >> (BYTE_SIZE*i)) & MASK));
        fprintf(stdout, i == 0 ? " " : ".");
    }
}

//Prints timestamp 
void print_ts(uint32_t sec, uint32_t usec) {
    fprintf(stdout, "%.6f ", (double)(sec) + ((double)(usec) / U_SEC_CONV_FACTOR));
}

//Prints diff between initial and final timestamp with no(!!!!) padding on end 
void print_ts_diff(uint32_t sec_i, uint32_t usec_i, uint32_t sec_f, uint32_t usec_f) {
    long sec_diff = (long)sec_f- (long)sec_i;
    long usec_diff = (long)usec_f - (long)usec_i;
    if (usec_diff < 0) 
    { 
        usec_diff = U_SEC_CONV_FACTOR + usec_diff; 
        sec_diff--; 
    }
    fprintf(stdout, "%.6f", (double)sec_diff + (double)usec_diff / U_SEC_CONV_FACTOR);
}


//Prints common address/port part of all outputs
void print_addr_port(uint32_t sip, uint16_t sport, uint32_t dip, uint16_t dport) {
    print_ip(sip);
    fprintf(stdout, "%d ", sport);
    print_ip(dip);
    fprintf(stdout, "%d ", dport);
}

//Returns whether timestamp a is earlier than timestamp b
bool is_earlier(uint32_t sec_a, uint32_t usec_a, uint32_t sec_b, uint32_t usec_b) {
    return sec_a < sec_b || ((sec_a == sec_b) && usec_a < usec_b);
}

//Returns whether timestamp a is later than timestamp b
bool is_later(uint32_t sec_a, uint32_t usec_a, uint32_t sec_b, uint32_t usec_b) {
    return sec_a > sec_b || ((sec_a == sec_b) && usec_a > usec_b);
}

void packet_print(FILE* fptr) {
    std::vector<ParsedPacket> packets = get_packets(fptr);

    for (ParsedPacket pkt : packets) {
        print_ts(pkt.sec_net, pkt.usec_net);
        print_addr_port(pkt.sip, pkt.sport, pkt.dip, pkt.dport);
        fprintf(stdout, "%u ", pkt.tot_len);
        fprintf(stdout, "%c ", pkt.protocol);
        fprintf(stdout, "%u ", pkt.transport_hdr_size);
        fprintf(stdout, "%u ", pkt.paylen);
        if (pkt.protocol == 'U') {
            fprintf(stdout, "- ");
        }
        else {
            fprintf(stdout,"%u ", pkt.seq);
        }
        if (pkt.protocol == 'U' || (pkt.th_flags & TH_ACK) != TH_ACK) {
            fprintf(stdout, "-\n");
        }
        else {
            fprintf(stdout, "%u\n", pkt.ack);
        }
    }
}

void info_update(NF_Flow_Info& curr_info, ParsedPacket pkt, bool include_udp) {
    //handle first time stamp
    if (is_earlier(pkt.sec_net, pkt.usec_net, curr_info.first_tv_sec, curr_info.first_tv_usec)) {
        curr_info.first_tv_sec = pkt.sec_net;
        curr_info.first_tv_usec = pkt.usec_net;
    }
    //handle final time stamp
    if (is_later(pkt.sec_net, pkt.usec_net, curr_info.final_tv_sec, curr_info.final_tv_usec)) {
        curr_info.final_tv_sec = pkt.sec_net;
        curr_info.final_tv_usec = pkt.usec_net;
    }
    //handle rtt timestamp
    if (!include_udp && pkt.paylen != 0 && 
        is_earlier(pkt.sec_net, pkt.usec_net, curr_info.first_seq_tv_sec, curr_info.first_seq_tv_usec)) {
        curr_info.update_seq(pkt);
    }

    curr_info.tot_pkts += 1;
    curr_info.tot_payload_bytes += pkt.paylen;
}

std::unordered_map<NF_Flow,NF_Flow_Info, NF_Hasher> get_flow_table(FILE* fptr, bool include_udp) {
    std::vector<ParsedPacket> packets = get_packets(fptr);

    std::unordered_map<NF_Flow,NF_Flow_Info, NF_Hasher> flow_table;

    for (ParsedPacket& pkt : packets) {  
        if (include_udp == true || pkt.protocol != 'U') {
            NF_Flow nf_flow(pkt);

            auto it = flow_table.find(nf_flow);
            if (it == flow_table.end()) {
                //create nf_flow value
                NF_Flow_Info nf_flow_info(pkt.sec_net, pkt.usec_net, pkt.sec_net, pkt.usec_net, 1, pkt.paylen);
                if (!include_udp && pkt.paylen != 0) {
                    nf_flow_info.update_seq(pkt);
                }

                //if this packet has an ack, add it to the vector that stores acks and timestamps
                if (!include_udp && ((pkt.th_flags & TH_ACK) == TH_ACK)) {
                    nf_flow_info.ack_timestamps = {{pkt.ack,{pkt.sec_net, pkt.usec_net}}};
                }
                
                flow_table[nf_flow] = nf_flow_info;
            }
            else {
                NF_Flow_Info& curr_info = it->second;

                info_update(curr_info, pkt, include_udp);

                //if this packet has an ack, add it to the vector that stores acks and timestamps
                if (!include_udp && (pkt.th_flags & TH_ACK) == TH_ACK) {
                    curr_info.ack_timestamps.push_back({pkt.ack, {pkt.sec_net, pkt.usec_net}});
                }
            }
        }
    }
    return flow_table;
}

void print_netflow(FILE * fptr) {
    std::unordered_map<NF_Flow,NF_Flow_Info, NF_Hasher> flow_table = get_flow_table(fptr, true);

    for (auto it : flow_table) {
        print_addr_port(it.first.sip, it.first.sport, it.first.dip, it.first.dport);
        fprintf(stdout, "%c ", it.first.protocol);
        print_ts(it.second.first_tv_sec,it.second.first_tv_usec);

        print_ts_diff(it.second.first_tv_sec, it.second.first_tv_usec, it.second.final_tv_sec, it.second.final_tv_usec);
        fprintf(stdout, " ");

        fprintf(stdout, "%u ", it.second.tot_pkts);
        fprintf(stdout, "%u\n", it.second.tot_payload_bytes);

    } 

}

//lambda to sort the vector by time 
void sort(std::vector<std::pair<uint32_t, std::pair<uint32_t, uint32_t>>>& ack_timestamps) {
    std::sort(ack_timestamps.begin(), ack_timestamps.end(), [](const auto& a, const auto& b) {
        const auto& a_time = a.second;
        const auto& b_time = b.second;
        if (a_time.first != b_time.first) { //if secs are not equal, compare by usecs
            return a_time.first < b_time.first;
        }
        else {
            return a_time.second < b_time.second; //if secs are equal, compare by usecs 
        }
    });
}

void print_rtt(FILE* fptr) {
    std::unordered_map<NF_Flow,NF_Flow_Info, NF_Hasher> flow_table = get_flow_table(fptr, false);

    for (auto it : flow_table) {
        print_addr_port(it.first.sip, it.first.sport, it.first.dip, it.first.dport);

        //get sequence number
        uint32_t first_seq = it.second.first_seq;

        //lookup reverse direction
        NF_Flow rev_flow(it.first.dip, it.first.sip, it.first.dport, it.first.sport, it.first.protocol);
        auto rev_it = flow_table.find(rev_flow);

        //If there is no RTT for this field
        if (rev_it == flow_table.end()) {
            fprintf(stdout, "-\n");
            continue;
        }
        //Otherwise get the vector of acks and timestamps
        const NF_Flow_Info& rev_info = rev_it->second;
        std::vector<std::pair<uint32_t, std::pair<uint32_t, uint32_t>>> ack_timestamps = rev_info.ack_timestamps;
        sort(ack_timestamps);   //sort by earliest time

        //find the first ack > seq and break loop 
        bool ack_found = false;
        for (const auto& pair : ack_timestamps) {
            const auto& ack = pair.first;
            const auto& t_ack = pair.second;
            //Check if ack # > seq# and ack timestamp > seq timestamp
            if (ack > first_seq && is_later(t_ack.first, t_ack.second,it.second.first_seq_tv_sec, it.second.first_seq_tv_usec)) {
                ack_found = true;
                print_ts_diff(it.second.first_seq_tv_sec, it.second.first_seq_tv_usec, t_ack.first, t_ack.second);
                fprintf(stdout, "\n");
                break;
            }
        }
        if (!ack_found) {
            fprintf(stdout, "-\n");
        }
    }
}

int main(int argc, char* argv[]) {
    parseargs(argc, argv);
    validate_arguments();

    //send valid args to methods
    if (cmd_line_flags == (ARG_PACKET_PRINT | ARG_TRACE_FILE)) {
        run_w_file(packet_print, trace_file_name);
    }
    else if (cmd_line_flags == (ARG_RTT | ARG_TRACE_FILE)) {
        run_w_file(print_rtt, trace_file_name);
    }
    else if (cmd_line_flags == (ARG_NET_FLOW | ARG_TRACE_FILE)) {
        run_w_file(print_netflow, trace_file_name);
    }
    else {
        fprintf(stderr, "error: no valid input given\n");
        exit(1);
    }

}
