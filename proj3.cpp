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
#define TH_ACK        0x10


unsigned short cmd_line_flags = 0;
char* trace_file_name = NULL;

//Type all output functions 
typedef void (*Out_Function)(FILE*);

//Defines a packet from trace file 
struct packet{
    //Garunteed to exist 
    uint32_t sec_net;
    uint32_t usec_net; 
    struct ether_header ethernet_hdr;

    //May or may not point to real headers
    struct iphdr *ip_hdr;
    struct udphdr *udp_hdr;
    struct tcphdr *tcp_hdr;
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


//Runs packet print mode 
/*
Each packet will produce a single line of output, as follows:
ts sip sport dip dport iplen protocol thlen paylen seqno ackno
dont print packets that dont have UDP or TCP as their transport prot
*/
std::vector<packet> get_packets(FILE* fptr) {
    std::vector<packet> packets;
    struct packet pkt;

    pkt.ip_hdr = nullptr;
    pkt.udp_hdr = nullptr;
    pkt.tcp_hdr = nullptr;

    bool ignore = false;

    while(fread(&pkt, 1, MIN_PKT_SIZE, fptr) == MIN_PKT_SIZE) {
        //first i need to look at the ip header and see if its ipv4 so that ill know whether or not to keep going
        //ill keep the packet stored in network byte order for now, and ntohs it if i need to l8r
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
            packets.push_back(pkt); 
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
    std::vector<packet> packets = get_packets(fptr);

    for (packet pkt : packets) {
        fprintf(stdout, "%.6f ", (double)(ntohl(pkt.sec_net)) + ((double)(ntohl(pkt.usec_net)) / U_SEC_CONV_FACTOR));
        print_ip(ntohl(pkt.ip_hdr->saddr));
        fprintf(stdout, "%d ", pkt.udp_hdr == nullptr ? ntohs(pkt.tcp_hdr->th_sport) : ntohs(pkt.udp_hdr->uh_sport));
        print_ip(ntohl(pkt.ip_hdr->daddr));
        fprintf(stdout, "%d ", pkt.udp_hdr == nullptr ? ntohs(pkt.tcp_hdr->th_dport) : ntohs(pkt.udp_hdr->uh_dport));
        fprintf(stdout, "%u ", ntohs(pkt.ip_hdr->tot_len));
        fprintf(stdout, pkt.udp_hdr == nullptr ? "T " : "U ");
        u_int transport_hdr_size = pkt.udp_hdr == nullptr ? ((DOFF_OFFSET*pkt.tcp_hdr->th_off)+TCP_MIN_SIZE) : UDP_HDR_SIZE;
        fprintf(stdout, "%u ", transport_hdr_size);
        u_int paylen = ntohs(pkt.ip_hdr->tot_len) - transport_hdr_size - IPV4_HDR_SIZE;
        fprintf(stdout, "%u ", paylen);
        if (pkt.tcp_hdr == nullptr) {
            fprintf(stdout, "- ");
        }
        else {
            fprintf(stdout,"%u ", ntohl(pkt.tcp_hdr->seq));
        }
        if (pkt.tcp_hdr == nullptr || (pkt.tcp_hdr->th_flags & TH_ACK) == TH_ACK) {
            fprintf(stdout, "-\n");
        }
        else {
            fprintf(stdout, "%u\n", ntohl(pkt.tcp_hdr->th_ack));
        }
    }
}

int main(int argc, char* argv[]) {
    parseargs(argc, argv);
    validate_arguments();

    //send valid args to methods
    if (cmd_line_flags == (ARG_PACKET_PRINT | ARG_TRACE_FILE)) {
        fprintf(stdout, "print %s\n", trace_file_name);
        run_w_file(packet_print, trace_file_name);
    }
    else if (cmd_line_flags == (ARG_RTT | ARG_TRACE_FILE)) {
        fprintf(stdout, "rtt %s\n", trace_file_name);
    }
    else if (cmd_line_flags == (ARG_NET_FLOW | ARG_TRACE_FILE)) {
        fprintf(stdout, "netflow %s\n", trace_file_name);
    }
    else {
        fprintf(stderr, "error: no valid input given\n");
        exit(1);
    }

}
