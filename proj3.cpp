/* 
Vincent Ave'Lallemant
vta9
proj3.cpp
10/18/2025

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

#define ARG_PACKET_PRINT 0x1
#define ARG_NET_FLOW 0x2
#define ARG_RTT 0x4
#define ARG_TRACE_FILE 0x8

#define DNE -1
#define MIN_PKT_SIZE 22
#define IPV4_TYPE 0x800
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

//Define hash_combine function...i dont really know
template <class T>
inline void hash_combine(std::size_t& seed, const T& v)
{
    std::hash<T> hasher;
    seed ^= hasher(v) + 0x9e3779b9 + (seed<<6) + (seed>>2);     //Holy constants 💀
}

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
    u_int paylen;

    uint32_t seq;
    uint32_t ack;

    uint8_t th_flags;

    ParsedPacket(Packet pkt) {
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

        }
        else {
            this->sport = ntohs(pkt.tcp_hdr->th_sport);
            this->dport = ntohs(pkt.tcp_hdr->th_dport);
            this->protocol = 'T';
            this->transport_hdr_size = (DOFF_OFFSET*pkt.tcp_hdr->th_off);
            this->seq =  ntohl(pkt.tcp_hdr->seq);
            this->ack = ntohl(pkt.tcp_hdr->th_ack);
            this->th_flags = pkt.tcp_hdr->th_flags;
        }

        this->paylen = this->tot_len - this->transport_hdr_size - IPV4_HDR_SIZE;
    }


};

//Defines a 5 tuple flow to be used as key in hash table
struct NF_Flow {
    uint32_t sip;
    uint32_t dip;
    uint16_t sport;
    uint16_t dport;
    char protocol;

    // NF_Flow() {
    //     sip = 0;
    //     dip = 0;
    //     sport = 0;
    //     dport = 0;
    //     protocol = '0';
    // }

    NF_Flow(ParsedPacket pkt) {
        this->sip = pkt.sip;
        this-> dip = pkt.dip;
        this->sport = pkt.sport;
        this->dport = pkt.dport;
        this->protocol = pkt.protocol;
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
        std::size_t seed = 0;
        hash_combine(seed, nf_flw.sip);
        hash_combine(seed, nf_flw.dip);
        hash_combine(seed, nf_flw.sport);
        hash_combine(seed, nf_flw.dport);
        hash_combine(seed, nf_flw.protocol);
        return seed;

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
//NEED TO DESTRUCT PACKETS AND FREE MEMORY AT SOME POINT (probably here)
std::vector<ParsedPacket> get_packets(FILE* fptr) {
    //std::vector<Packet> packets;
    std::vector<ParsedPacket> packets;
    struct Packet pkt;

    pkt.ip_hdr = nullptr;
    pkt.udp_hdr = nullptr;
    pkt.tcp_hdr = nullptr;

    bool ignore = false;

    while(fread(&pkt, 1, MIN_PKT_SIZE, fptr) == MIN_PKT_SIZE) {
        //first i need to look at the ip header and see if its ipv4 so that ill know whether or not to keep going
        //ill keep the Packet stored in network byte order for now, and ntohs it if i need to l8r
        if (ntohs(pkt.ethernet_hdr.ether_type) == IPV4_TYPE) {
            //malloc for iphdr pointer 
            pkt.ip_hdr = (struct iphdr *) malloc(IPV4_HDR_SIZE);
            //check if malloc worked 
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

                fread(pkt.udp_hdr, 1, UDP_HDR_SIZE, fptr);
            }
            else if (pkt.ip_hdr->protocol == TCP_PROTOCOL) {

                //malloc for tcp hdr pointer 
                pkt.tcp_hdr = (struct tcphdr *) malloc(TCP_MIN_SIZE);
                //check if malloc worked 
                if (pkt.tcp_hdr == nullptr) {
                    fprintf(stderr, "error: allocation failed\n");
                    exit(1);
                }

                fread(pkt.tcp_hdr, 1, TCP_MIN_SIZE, fptr);

                //multiply offset by 4 to get total length of header 
                //continue reading total length - 20 bytes of header
                int rem_length = (pkt.tcp_hdr->doff * DOFF_OFFSET) - TCP_MIN_SIZE;

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
                    u_int8_t* end_of_tcp = (u_int8_t*) pkt.tcp_hdr + TCP_MIN_SIZE;
                    fread(end_of_tcp, 1, rem_length, fptr);
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

            //packets.push_back(pkt); 
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


void packet_print(FILE* fptr) {
    std::vector<ParsedPacket> packets = get_packets(fptr);

    for (ParsedPacket pkt : packets) {
        fprintf(stdout, "%.6f ", (double)(pkt.sec_net) + ((double)(pkt.usec_net) / U_SEC_CONV_FACTOR));
        print_ip(pkt.sip);
        fprintf(stdout, "%d ", pkt.sport);
        print_ip(pkt.dip);
        fprintf(stdout, "%d ", pkt.dport);
        fprintf(stdout, "%u ", pkt.tot_len);
        fprintf(stdout, "%c ", pkt.protocol);
        //u_int transport_hdr_size = (pkt.ip_hdr->protocol == TCP_PROTOCOL ? ((DOFF_OFFSET*pkt.tcp_hdr->th_off)) : UDP_HDR_SIZE);
        fprintf(stdout, "%u ", pkt.transport_hdr_size);
        //u_int paylen = pkt.tot_len - pkt.transport_hdr_size - IPV4_HDR_SIZE;
        //fprintf(stdout, "%u ", paylen);
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

void netflow(FILE* fptr) {
    std::vector<ParsedPacket> packets = get_packets(fptr);

    std::unordered_map<NF_Flow,NF_Flow_Info, NF_Hasher> flow_table;

    NF_Flow_Info flag();

    for (ParsedPacket& pkt : packets) {  
        //first create key from parsed packet
        NF_Flow nf_flow(pkt);

        auto it = flow_table.find(nf_flow);

        if (it == flow_table.end()) {
            //not in table 
            //create nf_flow value
            NF_Flow_Info nf_flow_info(pkt.sec_net, pkt.usec_net, pkt.sec_net, pkt.usec_net, 1, pkt.paylen);
            //put into da table 
            flow_table[nf_flow] = nf_flow_info;
        }
        else {
            NF_Flow_Info& curr_info = it->second;
            //set first timestamp to earliest timestamp 

            //handle first time stamp
            uint32_t first_tv_sec = curr_info.first_tv_sec;
            uint32_t first_tv_usec = curr_info.first_tv_usec;
            //bias: current time stamp is earlier 
            if(curr_info.first_tv_sec > pkt.sec_net) {
                first_tv_sec = pkt.sec_net;
                first_tv_usec = pkt.usec_net;
            }
            else if (curr_info.first_tv_sec == pkt.sec_net){
                //if secs are equal, compare microsecs
                if (curr_info.first_tv_usec > pkt.usec_net) {
                    first_tv_sec = pkt.sec_net;
                    first_tv_usec = pkt.usec_net;
                }
            }

            //handle second timestamp 
            uint32_t final_tv_sec = curr_info.final_tv_sec;
            uint32_t final_tv_usec = curr_info.final_tv_usec;
            //bias: current time stamp is later
            if(curr_info.final_tv_sec < pkt.sec_net) {
                final_tv_sec = pkt.sec_net;
                final_tv_usec = pkt.usec_net;
            }
            else if (curr_info.final_tv_sec == pkt.sec_net){
                //if secs are equal, compare microsecs
                printf("stupid ahh seconds");
                if (curr_info.final_tv_usec < pkt.usec_net) {
                    final_tv_sec = pkt.sec_net;
                    final_tv_usec = pkt.usec_net;
                }
            }

            //increment # packets
            u_int tot_pkts = curr_info.tot_pkts + 1;

            //add to paylength
            u_int paylen = curr_info.tot_payload_bytes + pkt.paylen;

            //create struct with all of these fields
            NF_Flow_Info new_info(first_tv_sec, first_tv_usec, final_tv_sec, final_tv_usec, tot_pkts, paylen);

            //update entry in table
            flow_table[nf_flow] = new_info;
        }

    }
    //print
    for (auto it : flow_table) {
        print_ip(it.first.sip);
        fprintf(stdout, "%d ", it.first.sport);
        print_ip(it.first.dip);
        fprintf(stdout, "%d ", it.first.dport);
        fprintf(stdout, "%c ", it.first.protocol);
        fprintf(stdout, "%.6f ", (double)(it.second.first_tv_sec) + ((double)(it.second.first_tv_usec) / U_SEC_CONV_FACTOR));
        fprintf(stdout, "%.6f ", (double)(it.second.final_tv_sec-it.second.first_tv_sec) + ((double)(it.second.final_tv_usec-it.second.first_tv_usec) / U_SEC_CONV_FACTOR));
        fprintf(stdout, "%u ", it.second.tot_pkts);
        fprintf(stdout, "%u\n", it.second.tot_payload_bytes);

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
        fprintf(stdout, "rtt %s\n", trace_file_name);
    }
    else if (cmd_line_flags == (ARG_NET_FLOW | ARG_TRACE_FILE)) {
        //fprintf(stdout, "netflow %s\n", trace_file_name);
        run_w_file(netflow, trace_file_name);
    }
    else {
        fprintf(stderr, "error: no valid input given\n");
        exit(1);
    }

}
