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
ip tunnel add gre1 mode gre local $REMOTEPOINT remote $LOCALPOINT ttl 255
ip addr add 10.0.0.1/30 dev gre1
ip link set gre1 up
iptables -t nat -A POSTROUTING -s 10.0.0.0/30 ! -o gre+ -j SNAT --to-source $REMOTEPOINT
iptables -t nat -A POSTROUTING -s 10.69.1.0/24 ! -o gre+ -j SNAT --to-source $REMOTEPOINT
iptables -t nat -A POSTROUTING -s 10.69.2.0/24 ! -o gre+ -j SNAT --to-source $REMOTEPOINT
iptables -t nat -A POSTROUTING -s 10.69.3.0/24 ! -o gre+ -j SNAT --to-source $REMOTEPOINT
iptables -t nat -A POSTROUTING -s 10.69.4.0/24 ! -o gre+ -j SNAT --to-source $REMOTEPOINT
mkdir /etc/iptables/
touch /etc/iptables/add-iptable-rules.sh
touch /etc/iptables/rm-iptable-rules.sh
chmod +x /etc/iptables/add-iptable-rules.sh
chmod +x /etc/iptables/rm-iptable-rules.sh
echo -e "#!/bin/sh\n ip tunnel add gre1 mode gre local $REMOTEPOINT remote $LOCALPOINT ttl 255\n ip addr add 10.0.0.1/30 dev gre1\n ip link set gre1 up\n iptables -t nat -A POSTROUTING -s 10.0.0.0/30 ! -o gre+ -j SNAT --to-source $REMOTEPOINT\n iptables -t nat -A POSTROUTING -s 10.69.1.0/24 ! -o gre+ -j SNAT --to-source $REMOTEPOINT\n iptables -t nat -A POSTROUTING -s 10.69.2.0/24 ! -o gre+ -j SNAT --to-source $REMOTEPOINT\n iptables -t nat -A POSTROUTING -s 10.69.3.0/24 ! -o gre+ -j SNAT --to-source $REMOTEPOINT\n iptables -t nat -A POSTROUTING -s 10.69.4.0/24 ! -o gre+ -j SNAT --to-source $REMOTEPOINT" |  tee -a /etc/iptables/add-iptable-rules.sh
echo -e "#!/bin/sh\n iptables -t nat -F" |  tee -a /etc/iptables/rm-iptable-rules.sh
echo "[Unit]
Description=iptables rules for Covernet
Before=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=/etc/iptables/add-iptable-rules.sh
ExecStop=/etc/iptables/rm-iptable-rules.sh
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target" >/etc/systemd/system/iptables-covernet.service
systemctl daemon-reload
systemctl enable iptables-covernet
systemctl start iptables-covernet
sed -i '/.*net.ipv4.ip.*/s/^#//g' /etc/sysctl.conf
sysctl -p
