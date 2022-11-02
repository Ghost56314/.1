#!/bin/bash
function Site2Site(){
LOCALIP=$(ip route get 8.8.8.8 | awk -F"src " 'NR==1{split($2,a," ");print a[1]}')
        until [[ $LOCALPOINT =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
        read -rp "Public address or hostname Of This Server: " -e -i "$LOCALIP" LOCALPOINT
done
        until [[ $REMOTEPOINT =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
        read -rp "Public address or hostname of Remote Server: " -e REMOTEPOINT
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
}
function Site2SiteAS(){
clear
apt install anytun -y
mkdir -p /etc/tunnel
touch /etc/tunnel/start-covernet-tunnel.sh
touch /etc/tunnel/stop-covernet-tunnel.sh
chmod +x /etc/tunnel/start-covernet-tunnel.sh
chmod +x /etc/tunnel/stop-covernet-tunnel.sh
sudo echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
sudo sysctl -p
echo "[Unit]
After=network.target
StartLimitIntervalSec=0
[Service]
Type=simple
Restart=always
RestartSec=1
ExecStart=/etc/tunnel/start-covernet-tunnel.sh
ExecStop=/etc/tunnel/stop-covernet-tunnel.sh
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target" >/etc/systemd/system/covernet-tunnel.service
chmod +x /etc/systemd/system/covernet-tunnel.service
systemctl daemon-reload
systemctl enable --now covernet-tunnel
LOCALIP=$(ip route get 8.8.8.8 | awk -F"src " 'NR==1{split($2,a," ");print a[1]}')
until [[ $LOCALPOINT =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
read -rp "Public address or hostname Of This Server: " -e -i "$LOCALIP" LOCALPOINT
done
until [[ $REMOTEPOINT =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
read -rp "Public address or hostname of Remote Server: " -e REMOTEPOINT
done
cat > /etc/tunnel/start-covernet-tunnel.sh <<EOF
#!/bin/bash
anytun -r $REMOTEPOINT -t tun -n 10.0.0.1/30 -c aes-ctr-256 -k aes-ctr-256 -E covernet -e right
iptables -t nat -A POSTROUTING -s 192.168.123.0/30 ! -o tun+ -j SNAT --to-source $LOCALPOINT
iptables -t nat -A POSTROUTING -s 172.27.224.0/20 ! -o tun+ -j SNAT --to-source $LOCALPOINT
EOF
cat > /etc/tunnel/stop-covernet-tunnel.sh <<EOF
#!/bin/bash
pkill -9 anytun
iptables -t nat -D POSTROUTING -s 192.168.123.0/30 ! -o tun+ -j SNAT --to-source $LOCALPOINT
iptables -t nat -D POSTROUTING -s 172.27.224.0/20 ! -o tun+ -j SNAT --to-source $LOCALPOINT
EOF
systemctl restart covernet-tunnel
echo "Enjoy it... :)"
sleep 2
}
function Selection(){
	Passwd
	choice=0
	while [ $choice -eq 0 ]
	do
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
                                                                                                    
                                                                                               \e[0m \e[0;35m V2.6.1 \e[0m "
	echo
	echo
	echo -e "\e[0;31m1) Setup Site2Site General \e[0m"
	echo -e "\e[0;33m2) Setup Site2Site OpenVPN-AS \e[0m"
	echo
	echo
	echo "0) Exit"
	echo
	read -rp "Select a number:" Selection
	if [ $Selection -gt 2 ]
	then
		echo "The variable is greater than 2."
		sleep 1s
	elif [ $Selection -eq 1 ]
	then
		Site2Site
	elif [ $Selection -eq 2 ]
	then
		Site2SiteAS
	elif [ $Selection -eq 0 ]
	then
		choice=1
	else
		echo "Exit"
	fi
	done
}
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
