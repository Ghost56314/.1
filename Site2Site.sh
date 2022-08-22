#!/bin/bash
Passwd
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
mkdir /etc/iptables/
touch /etc/iptables/add-iptable-rules.sh
touch /etc/iptables/rm-iptable-rules.sh
chmod +x /etc/iptables/add-iptable-rules.sh
chmod +x /etc/iptables/rm-iptable-rules.sh
echo -e "#!/bin/sh\n ip tunnel add gre1 mode gre local $ENDPOINT remote $IRPOINT ttl 255\n ip addr add 10.0.0.1/30 dev gre1\n ip link set gre1 up\n iptables -t nat -A POSTROUTING -s 10.0.0.0/30 ! -o gre+ -j SNAT --to-source $ENDPOINT\n iptables -t nat -A POSTROUTING -s 10.69.1.0/24 ! -o gre+ -j SNAT --to-source $ENDPOINT\n iptables -t nat -A POSTROUTING -s 10.69.2.0/24 ! -o gre+ -j SNAT --to-source $ENDPOINT\n iptables -t nat -A POSTROUTING -s 10.69.3.0/24 ! -o gre+ -j SNAT --to-source $ENDPOINT\n iptables -t nat -A POSTROUTING -s 10.69.4.0/24 ! -o gre+ -j SNAT --to-source $ENDPOINT" |  tee -a /etc/iptables/add-iptable-rules.sh
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
Selection
