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
#include <netinet/ip.h> 
#include <unordered_map>

#define ARG_PACKET_PRINT 0x1
#define ARG_NET_FLOW 0x2
#define ARG_RTT 0x4
#define ARG_TRACE_FILE 0x10

#define DNE -1

unsigned short cmd_line_flags = 0;
char* trace_file_name = NULL;

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

int main(int argc, char* argv[]) {
    parseargs(argc, argv);
    validate_arguments();

    //send valid args to methods
    if (cmd_line_flags == (ARG_PACKET_PRINT | ARG_TRACE_FILE)) {
        fprintf(stdout, "print %s\n", trace_file_name);
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
