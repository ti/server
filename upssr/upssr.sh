#!/bin/bash
# Create a new inspection chain named SSR in the NAT table.
iptables -t nat -N SSR
# Ignore native IP and server IP
iptables -t nat -A SSR -d 119.28.181.169 -j RETURN
iptables -t nat -A SSR -d 35.197.92.231 -j RETURN
# Ignore various private addresses
iptables -t nat -A SSR -d 0.0.0.0/8 -j RETURN
iptables -t nat -A SSR -d 10.0.0.0/8 -j RETURN
iptables -t nat -A SSR -d 127.0.0.0/8 -j RETURN
iptables -t nat -A SSR -d 169.254.0.0/16 -j RETURN
iptables -t nat -A SSR -d 172.16.0.0/12 -j RETURN
iptables -t nat -A SSR -d 192.168.0.0/16 -j RETURN
iptables -t nat -A SSR -d 224.0.0.0/4 -j RETURN
iptables -t nat -A SSR -d 240.0.0.0/4 -j RETURN
# Others are forwarded to 10801 (ss-redir port)
iptables -t nat -A SSR -p tcp -j REDIRECT --to-ports 10801
# Add the SSR check chain to the OUTPUT check chain, so that the local external traffic is proxyed.
iptables -t nat -A OUTPUT -p tcp -j SSR
# For the router, add the SSR check chain to the FORWARD check chain to implement transparent proxy in the LAN.
iptables -t nat -A FORWARD -p tcp -j SSR
read -p "SSR is in the agent, press Enter to exit the agent"
iptables -t nat -F
echo "SSR proxy exited"
exit 0
