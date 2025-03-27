#!/bin/bash

# Default to cleaning both IPv4 and IPv6 rules
CLEAN_IPV4=true
CLEAN_IPV6=true

# Optional CLI switches to limit scope
while getopts "46" opt; do
  case $opt in
    4)
      CLEAN_IPV4=true
      CLEAN_IPV6=false
      ;;
    6)
      CLEAN_IPV4=false
      CLEAN_IPV6=true
      ;;
    *)
      exit 1
      ;;
  esac
done

TCP_FILTERED=50503
UDP_FILTERED=50504

# Remove ip4 filtered
if [ "$CLEAN_IPV4" = true ]; then
  sudo iptables -D INPUT -p tcp --dport $TCP_FILTERED -j DROP 2>/dev/null
  sudo iptables -D INPUT -p udp --dport $UDP_FILTERED -j DROP 2>/dev/null
fi

# Remove ipv6 filterd
if [ "$CLEAN_IPV6" = true ]; then
  sudo ip6tables -D INPUT -p tcp --dport $TCP_FILTERED -j DROP 2>/dev/null
  sudo ip6tables -D INPUT -p udp --dport $UDP_FILTERED -j DROP 2>/dev/null
fi

# Kill background netcat pids
for PORT in 50501 50502 50505; do
  pkill -f "nc.*$PORT"
done
