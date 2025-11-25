# NetFlow Router Simulator

This project implements a simplified router traffic analyzer that processes a binary packet trace and outputs network statistics in three selectable modes: packet inspection, NetFlow summaries, and RTT estimation.
This project is inspired by CSDS 325/425 Project 3, but extends it with a Python analysis layer using pandas and matplotlib for large-scale RTT and latency analysis.

## Features

Packet Printing Mode (-p) – Prints details for each valid IPv4 TCP/UDP packet.

NetFlow Mode (-n) – Aggregates traffic into flows and outputs statistics per 5-tuple.

RTT Mode (-r) – Computes the first observed RTT for each TCP flow.

## Usage
./proj3 [-p | -n | -r] -f <trace_file>


You must specify exactly one mode and a trace file.

Examples:

./proj3 -p -f example.trace
./proj3 -n -f example.trace
./proj3 -r -f example.trace

## Requirements

Written in C++

Uses standard libraries only (no third-party dependencies)

Compiled using the provided Makefile:

make

## Notes

Only IPv4 packets using TCP or UDP are processed.

Non-IPv4 or non-TCP/UDP packets are read, but only processed up to the end of their headers.

