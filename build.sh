#!/bin/sh

SOURCE_FILE="netflow_exporter_v5.cpp"
OUTPUT_FILE="netflow_exporter_v5"

echo "Cleaning up old build"
rm -f $OUTPUT_FILE

g++ -std=c++11 -g0 -O2 -Wall -Wextra -pedantic -lpcap -o $OUTPUT_FILE $SOURCE_FILE

if [ $? -eq 0 ]; then
    echo "Compilation Successful!"

    # ./$OUTPUT_FILE localhost:9905 data/network_traffic.pcap
else
    echo "Compilation failed."
fi
