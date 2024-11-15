#!/bin/sh

SOURCE_FILE="netflow_exporter_v5.cpp"
OUTPUT_FILE="netflow_exporter_v5"

echo "Cleaning up old build"
rm -f $OUTPUT_FILE

g++ -std=c++11 -g0 -O2 -Wall -Wextra -pedantic -o $OUTPUT_FILE -v $SOURCE_FILE -lpcap

if [ $? -eq 0 ]; then
    echo "Compilation Successful!"

    ./$OUTPUT_FILE 127.0.0.1:9995 Data/network_traffic.pcap
    # ./$OUTPUT_FILE 127.0.0.1:9995 Data/large.pcap
else
    echo "Compilation failed."
fi
