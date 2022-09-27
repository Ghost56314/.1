#!/bin/bash
function Passwd(){
        ACTUAL="u1rGiEkhAN"
        read -s -p "Password: " enteredpass
        echo ""
        if [ "$enteredpass" != "$ACTUAL" ]
        then
                echo "Sorry" && echo "exiting"
                exit 0
        fi
}
Passwd
clear
        printf " %-40s \n" "`date`"
        echo
        echo
        echo -e "\e[0;34m
 ██████  ██████  ██    ██ ███████ ██████  ███    ██ ███████ ████████     ██    ██ ██████  ███    ██
██      ██    ██ ██    ██ ██      ██   ██ ████   ██ ██         ██        ██    ██ ██   ██ ████   ██
██      ██    ██ ██    ██ █████   ██████  ██ ██  ██ █████      ██        ██    ██ ██████  ██ ██  ██
██      ██    ██  ██  ██  ██      ██   ██ ██  ██ ██ ██         ██         ██  ██  ██      ██  ██ ██
 ██████  ██████    ████   ███████ ██   ██ ██   ████ ███████    ██          ████   ██      ██   ████
                                                                                               \e[0m \e[0;35m V2.2 \e[0m "
        echo
        echo

LOCALIP=$(curl -s https://api.ipify.org)
        until [[ $LOCALPOINT =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
        read -rp "Public address or hostname Of This Server: " -e -i "$LOCALIP" LOCALPOINT
done
REMOTEIP=$(curl -s https://api.ipify.org)
        until [[ $REMOTEPOINT =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
        read -rp "Public address or hostname of Remote Server: " -e -i "$REMOTEIP" REMOTEPOINT
done
echo "[Unit]
Description=iptables rules for Covernet
Before=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=modprobe ip_gre
ExecStart=ip tunnel add gre1 mode gre local $LOCALPOINT remote $REMOTEPOINT ttl 255
ExecStart=ip addr add 10.0.0.1/30 dev gre1
ExecStart=ip link set gre1 up
ExecStart=iptables -t nat -A POSTROUTING -s 10.0.0.0/30 ! -o gre+ -j SNAT --to-source $LOCALPOINT
ExecStart=iptables -t nat -A POSTROUTING -s 10.69.1.0/24 ! -o gre+ -j SNAT --to-source $LOCALPOINT
ExecStart=iptables -t nat -A POSTROUTING -s 10.69.2.0/24 ! -o gre+ -j SNAT --to-source $LOCALPOINT
ExecStart=iptables -t nat -A POSTROUTING -s 10.69.3.0/24 ! -o gre+ -j SNAT --to-source $LOCALPOINT
ExecStart=iptables -t nat -A POSTROUTING -s 10.69.4.0/24 ! -o gre+ -j SNAT --to-source $LOCALPOINT
ExecStop=ip link delete gre1
ExecStop=iptables -t nat -D POSTROUTING -s 10.0.0.0/30 ! -o gre+ -j SNAT --to-source $LOCALPOINT
ExecStop=iptables -t nat -D POSTROUTING -s 10.69.1.0/24 ! -o gre+ -j SNAT --to-source $LOCALPOINT
ExecStop=iptables -t nat -D POSTROUTING -s 10.69.2.0/24 ! -o gre+ -j SNAT --to-source $LOCALPOINT
ExecStop=iptables -t nat -D POSTROUTING -s 10.69.3.0/24 ! -o gre+ -j SNAT --to-source $LOCALPOINT
ExecStop=iptables -t nat -D POSTROUTING -s 10.69.4.0/24 ! -o gre+ -j SNAT --to-source $LOCALPOINT
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target" >/etc/systemd/system/gre-tunnel.service
systemctl daemon-reload
systemctl enable --now gre-tunnel
systemctl start gre-tunnel
sed -i '/.*net.ipv4.ip.*/s/^#//g' /etc/sysctl.conf
sysctl -p
