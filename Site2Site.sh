#!/bin/bash
PUBLICIP=$(curl -s https://api.ipify.org)
        until [[ $ENDPOINT =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
        read -rp "Public Foreign address or hostname: " -e -i "$PUBLICIP" ENDPOINT
done

IRIP=$(curl -s https://api.ipify.org)
        until [[ $IRPOINT =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
        read -rp "Public IRAN address or hostname: " -e -i "$IRIP" IRPOINT
done

ip tunnel add gre1 mode gre local $ENDPOINT remote $IRPOINT ttl 255
ip addr add 10.0.0.1/30 dev gre1
ip link set gre1 up
iptables -t nat -A POSTROUTING -s 10.0.0.0/30 ! -o gre+ -j SNAT --to-source $ENDPOINT
iptables -t nat -A POSTROUTING -s 10.69.1.0/24 ! -o gre+ -j SNAT --to-source $ENDPOINT
iptables -t nat -A POSTROUTING -s 10.69.2.0/24 ! -o gre+ -j SNAT --to-source $ENDPOINT
iptables -t nat -A POSTROUTING -s 10.69.3.0/24 ! -o gre+ -j SNAT --to-source $ENDPOINT
iptables -t nat -A POSTROUTING -s 10.69.4.0/24 ! -o gre+ -j SNAT --to-source $ENDPOINT

sed -i '/.*net.ipv4.ip.*/s/^#//g' /etc/sysctl.conf
sysctl -p
