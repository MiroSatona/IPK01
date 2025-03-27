#!/bin/bash

# Default to IPv4 loopback
ADDRESS="127.0.0.1"

# Parse options
while getopts "46" opt; do
  case $opt in
    4) ADDRESS="127.0.0.1" ;;
    6) ADDRESS="::1" ;;
    *) exit 1 ;;
  esac
done

# Define ports
TCP_PORT1=50501
TCP_PORT2=50502
TCP_FILTERED=50503

UDP_PORT=50505
UDP_FILTERED=50504

# Select firewall tool
if [[ "$ADDRESS" == "::1" ]]; then
  FW_CMD="ip6tables"
else
  FW_CMD="iptables"
fi

# Launch open TCP ports
nc -l $ADDRESS $TCP_PORT1 >/dev/null &
nc -l $ADDRESS $TCP_PORT2 >/dev/null &

# Launch open UDP port
nc -u -l $ADDRESS $UDP_PORT >/dev/null &

sleep 1

# Add rules for filtered ports
sudo $FW_CMD -A INPUT -p tcp --dport $TCP_FILTERED -j DROP
sudo $FW_CMD -A INPUT -p udp --dport $UDP_FILTERED -j DROP

