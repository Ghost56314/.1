#!/bin/bash
# shellcheck disable=SC1091,SC2164,SC2034,SC1072,SC1073,SC1009
function installopenvpn(){  
#!/bin/bash
preinst

# Detect Debian users running the script with "sh" instead of bash
if readlink /proc/$$/exe | grep -q "dash"; then
	echo 'This installer needs to be run with "bash", not "sh".'
	exit
fi

# Discard stdin. Needed when running from an one-liner which includes a newline
read -N 999999 -t 0.001

# Detect OpenVZ 6
if [[ $(uname -r | cut -d "." -f 1) -eq 2 ]]; then
	echo "The system is running an old kernel, which is incompatible with this installer."
	exit
fi

# Detect OS
# $os_version variables aren't always in use, but are kept here for convenience
if grep -qs "ubuntu" /etc/os-release; then
	os="ubuntu"
	os_version=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.')
	group_name="nogroup"
elif [[ -e /etc/debian_version ]]; then
	os="debian"
	os_version=$(grep -oE '[0-9]+' /etc/debian_version | head -1)
	group_name="nogroup"
elif [[ -e /etc/almalinux-release || -e /etc/rocky-release || -e /etc/centos-release ]]; then
	os="centos"
	os_version=$(grep -shoE '[0-9]+' /etc/almalinux-release /etc/rocky-release /etc/centos-release | head -1)
	group_name="nobody"
elif [[ -e /etc/fedora-release ]]; then
	os="fedora"
	os_version=$(grep -oE '[0-9]+' /etc/fedora-release | head -1)
	group_name="nobody"
else
	echo "This installer seems to be running on an unsupported distribution.
Supported distros are Ubuntu, Debian, AlmaLinux, Rocky Linux, CentOS and Fedora."
	exit
fi

if [[ "$os" == "ubuntu" && "$os_version" -lt 1804 ]]; then
	echo "Ubuntu 18.04 or higher is required to use this installer.
This version of Ubuntu is too old and unsupported."
	exit
fi

if [[ "$os" == "debian" && "$os_version" -lt 9 ]]; then
	echo "Debian 9 or higher is required to use this installer.
This version of Debian is too old and unsupported."
	exit
fi

if [[ "$os" == "centos" && "$os_version" -lt 7 ]]; then
	echo "CentOS 7 or higher is required to use this installer.
This version of CentOS is too old and unsupported."
	exit
fi

# Detect environments where $PATH does not include the sbin directories
if ! grep -q sbin <<< "$PATH"; then
	echo '$PATH does not include sbin. Try using "su -" instead of "su".'
	exit
fi

if [[ "$EUID" -ne 0 ]]; then
	echo "This installer needs to be run with superuser privileges."
	exit
fi

if [[ ! -e /dev/net/tun ]] || ! ( exec 7<>/dev/net/tun ) 2>/dev/null; then
	echo "The system does not have the TUN device available.
TUN needs to be enabled before running this installer."
	exit
fi

new_client () {
	# Generates the custom client.ovpn
	{
	cat /etc/openvpn/server/client-common.txt
	echo "<ca>"
	cat /etc/openvpn/server/easy-rsa/pki/ca.crt
	echo "</ca>"
	echo "<cert>"
	sed -ne '/BEGIN CERTIFICATE/,$ p' /etc/openvpn/server/easy-rsa/pki/issued/"$client".crt
	echo "</cert>"
	echo "<key>"
	cat /etc/openvpn/server/easy-rsa/pki/private/"$client".key
	echo "</key>"
	echo "<tls-crypt>"
	sed -ne '/BEGIN OpenVPN Static key/,$ p' /etc/openvpn/server/tc.key
	echo "</tls-crypt>"
	} > ~/"$client".ovpn
}

if [[ ! -e /etc/openvpn/server/server.conf ]]; then
	# Detect some Debian minimal setups where neither wget nor curl are installed
	if ! hash wget 2>/dev/null && ! hash curl 2>/dev/null; then
		echo "Wget is required to use this installer."
		read -n1 -r -p "Press any key to install Wget and continue..."
		apt-get update
		apt-get install -y wget
	fi
	clear
	echo 'Welcome to this OpenVPN installer!'
	# If system has a single IPv4, it is selected automatically. Else, ask the user
	if [[ $(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}') -eq 1 ]]; then
		ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}')
	else
		number_of_ip=$(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}')
		echo
		echo "Which IPv4 address should be used?"
		ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | nl -s ') '
		read -p "IPv4 address [1]: " ip_number
		until [[ -z "$ip_number" || "$ip_number" =~ ^[0-9]+$ && "$ip_number" -le "$number_of_ip" ]]; do
			echo "$ip_number: invalid selection."
			read -p "IPv4 address [1]: " ip_number
		done
		[[ -z "$ip_number" ]] && ip_number="1"
		ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | sed -n "$ip_number"p)
	fi
	# If $ip is a private IP address, the server must be behind NAT
	if echo "$ip" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
		echo
		echo "This server is behind NAT. What is the public IPv4 address or hostname?"
		# Get public IP and sanitize with grep
		get_public_ip=$(grep -m 1 -oE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' <<< "$(wget -T 10 -t 1 -4qO- "http://ip1.dynupdate.no-ip.com/" || curl -m 10 -4Ls "http://ip1.dynupdate.no-ip.com/")")
		read -p "Public IPv4 address / hostname [$get_public_ip]: " public_ip
		# If the checkip service is unavailable and user didn't provide input, ask again
		until [[ -n "$get_public_ip" || -n "$public_ip" ]]; do
			echo "Invalid input."
			read -p "Public IPv4 address / hostname: " public_ip
		done
		[[ -z "$public_ip" ]] && public_ip="$get_public_ip"
	fi
	# If system has a single IPv6, it is selected automatically
	if [[ $(ip -6 addr | grep -c 'inet6 [23]') -eq 1 ]]; then
		ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}')
	fi
	# If system has multiple IPv6, ask the user to select one
	if [[ $(ip -6 addr | grep -c 'inet6 [23]') -gt 1 ]]; then
		number_of_ip6=$(ip -6 addr | grep -c 'inet6 [23]')
		echo
		echo "Which IPv6 address should be used?"
		ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | nl -s ') '
		read -p "IPv6 address [1]: " ip6_number
		until [[ -z "$ip6_number" || "$ip6_number" =~ ^[0-9]+$ && "$ip6_number" -le "$number_of_ip6" ]]; do
			echo "$ip6_number: invalid selection."
			read -p "IPv6 address [1]: " ip6_number
		done
		[[ -z "$ip6_number" ]] && ip6_number="1"
		ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | sed -n "$ip6_number"p)
	fi
	echo
	echo "Which protocol should OpenVPN use?"
	echo "   1) UDP (recommended)"
	echo "   2) TCP"
	read -p "Protocol [1]: " protocol
	until [[ -z "$protocol" || "$protocol" =~ ^[12]$ ]]; do
		echo "$protocol: invalid selection."
		read -p "Protocol [1]: " protocol
	done
	case "$protocol" in
		1|"") 
		protocol=udp
		;;
		2) 
		protocol=tcp
		;;
	esac
	echo
	echo "What port should OpenVPN listen to?"
	read -p "Port [94]: " port
	until [[ -z "$port" || "$port" =~ ^[0-9]+$ && "$port" -le 65535 ]]; do
		echo "$port: invalid port."
		read -p "Port [94]: " port
	done
	[[ -z "$port" ]] && port="94"
	echo
	echo "Select a DNS server for the clients:"
	echo "   1) Current system resolvers"
	echo "   2) Google"
	echo "   3) 1.1.1.1"
	echo "   4) OpenDNS"
	echo "   5) Quad9"
	echo "   6) AdGuard"
	read -p "DNS server [1]: " dns
	until [[ -z "$dns" || "$dns" =~ ^[1-6]$ ]]; do
		echo "$dns: invalid selection."
		read -p "DNS server [1]: " dns
	done
	echo
	echo "Enter a name for the first client:"
	read -p "Name [client]: " unsanitized_client
	# Allow a limited set of characters to avoid conflicts
	client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
	[[ -z "$client" ]] && client="client"
	echo
	echo "OpenVPN installation is ready to begin."
	# Install a firewall if firewalld or iptables are not already available
	if ! systemctl is-active --quiet firewalld.service && ! hash iptables 2>/dev/null; then
		if [[ "$os" == "centos" || "$os" == "fedora" ]]; then
			firewall="firewalld"
			# We don't want to silently enable firewalld, so we give a subtle warning
			# If the user continues, firewalld will be installed and enabled during setup
			echo "firewalld, which is required to manage routing tables, will also be installed."
		elif [[ "$os" == "debian" || "$os" == "ubuntu" ]]; then
			# iptables is way less invasive than firewalld so no warning is given
			firewall="iptables"
		fi
	fi
	read -n1 -r -p "Press any key to continue..."
	# If running inside a container, disable LimitNPROC to prevent conflicts
	if systemd-detect-virt -cq; then
		mkdir /etc/systemd/system/openvpn-server@server.service.d/ 2>/dev/null
		echo "[Service]
LimitNPROC=infinity" > /etc/systemd/system/openvpn-server@server.service.d/disable-limitnproc.conf
	fi
	if [[ "$os" = "debian" || "$os" = "ubuntu" ]]; then
		apt-get update
		apt-get install -y openvpn openssl ca-certificates $firewall
	elif [[ "$os" = "centos" ]]; then
		yum install -y epel-release
		yum install -y openvpn openssl ca-certificates tar $firewall
	else
		# Else, OS must be Fedora
		dnf install -y openvpn openssl ca-certificates tar $firewall
	fi
	# If firewalld was just installed, enable it
	if [[ "$firewall" == "firewalld" ]]; then
		systemctl enable --now firewalld.service
	fi
	# Get easy-rsa
	easy_rsa_url='https://github.com/OpenVPN/easy-rsa/releases/download/v3.1.0/EasyRSA-3.1.0.tgz'
	mkdir -p /etc/openvpn/server/easy-rsa/
	{ wget -qO- "$easy_rsa_url" 2>/dev/null || curl -sL "$easy_rsa_url" ; } | tar xz -C /etc/openvpn/server/easy-rsa/ --strip-components 1
	chown -R root:root /etc/openvpn/server/easy-rsa/
	cd /etc/openvpn/server/easy-rsa/
	# Create the PKI, set up the CA and the server and client certificates
	./easyrsa init-pki
	./easyrsa --batch build-ca nopass
	EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-server-full server nopass
	EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-client-full "$client" nopass
	EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
	# Move the stuff we need
	cp pki/ca.crt pki/private/ca.key pki/issued/server.crt pki/private/server.key pki/crl.pem /etc/openvpn/server
	# CRL is read with each client connection, while OpenVPN is dropped to nobody
	chown nobody:"$group_name" /etc/openvpn/server/crl.pem
	# Without +x in the directory, OpenVPN can't run a stat() on the CRL file
	chmod o+x /etc/openvpn/server/
	# Generate key for tls-crypt
	openvpn --genkey --secret /etc/openvpn/server/tc.key
	# Create the DH parameters file using the predefined ffdhe2048 group
	echo '-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz
+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a
87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7
YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi
7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD
ssbzSibBsu/6iGtCOGEoXJf//////////wIBAg==
-----END DH PARAMETERS-----' > /etc/openvpn/server/dh.pem
	# Generate server.conf
	echo "local $ip
port $port
proto $protocol
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
auth SHA512
tls-crypt tc.key
topology subnet
server 10.69.1.0 255.255.255.0" > /etc/openvpn/server/server.conf
	# IPv6
	if [[ -z "$ip6" ]]; then
		echo 'push "redirect-gateway def1 bypass-dhcp"' >> /etc/openvpn/server/server.conf
	else
		echo 'server-ipv6 fddd:1194:1194:1194::/64' >> /etc/openvpn/server/server.conf
		echo 'push "redirect-gateway def1 ipv6 bypass-dhcp"' >> /etc/openvpn/server/server.conf
	fi
	echo 'ifconfig-pool-persist ipp.txt' >> /etc/openvpn/server/server.conf
	# DNS
	case "$dns" in
		1|"")
			# Locate the proper resolv.conf
			# Needed for systems running systemd-resolved
			if grep -q '^nameserver 127.0.0.53' "/etc/resolv.conf"; then
				resolv_conf="/run/systemd/resolve/resolv.conf"
			else
				resolv_conf="/etc/resolv.conf"
			fi
			# Obtain the resolvers from resolv.conf and use them for OpenVPN
			grep -v '^#\|^;' "$resolv_conf" | grep '^nameserver' | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | while read line; do
				echo "push \"dhcp-option DNS $line\"" >> /etc/openvpn/server/server.conf
			done
		;;
		2)
			echo 'push "dhcp-option DNS 8.8.8.8"' >> /etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 8.8.4.4"' >> /etc/openvpn/server/server.conf
		;;
		3)
			echo 'push "dhcp-option DNS 1.1.1.1"' >> /etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 1.0.0.1"' >> /etc/openvpn/server/server.conf
		;;
		4)
			echo 'push "dhcp-option DNS 208.67.222.222"' >> /etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 208.67.220.220"' >> /etc/openvpn/server/server.conf
		;;
		5)
			echo 'push "dhcp-option DNS 9.9.9.9"' >> /etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 149.112.112.112"' >> /etc/openvpn/server/server.conf
		;;
		6)
			echo 'push "dhcp-option DNS 94.140.14.14"' >> /etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 94.140.15.15"' >> /etc/openvpn/server/server.conf
		;;
	esac
	echo "keepalive 10 120
cipher AES-256-CBC
user nobody
group $group_name
persist-key
persist-tun
verb 3
duplicate-cn
management 0.0.0.0 7506
plugin /usr/lib/openvpn/radiusplugin.so  /usr/lib/openvpn/radiusplugin.cnf
log /var/log/openvpn/openvpn.log
status /var/log/openvpn/status-openvpn.log
crl-verify crl.pem" >> /etc/openvpn/server/server.conf
	if [[ "$protocol" = "udp" ]]; then
		echo "explicit-exit-notify" >> /etc/openvpn/server/server.conf
	fi
	# Enable net.ipv4.ip_forward for the system
	echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-openvpn-forward.conf
	# Enable without waiting for a reboot or service restart
	echo 1 > /proc/sys/net/ipv4/ip_forward
	if [[ -n "$ip6" ]]; then
		# Enable net.ipv6.conf.all.forwarding for the system
		echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.d/99-openvpn-forward.conf
		# Enable without waiting for a reboot or service restart
		echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
	fi
	if systemctl is-active --quiet firewalld.service; then
		# Using both permanent and not permanent rules to avoid a firewalld
		# reload.
		# We don't use --add-service=openvpn because that would only work with
		# the default port and protocol.
		firewall-cmd --add-port="$port"/"$protocol"
		firewall-cmd --zone=trusted --add-source=10.69.1.0/24
		firewall-cmd --permanent --add-port="$port"/"$protocol"
		firewall-cmd --permanent --zone=trusted --add-source=10.69.1.0/24
		# Set NAT for the VPN subnet
		firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.69.1.0/24 ! -d 10.69.1.0/24 -j SNAT --to "$ip"
		firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.69.1.0/24 ! -d 10.69.1.0/24 -j SNAT --to "$ip"
		if [[ -n "$ip6" ]]; then
			firewall-cmd --zone=trusted --add-source=fddd:1194:1194:1194::/64
			firewall-cmd --permanent --zone=trusted --add-source=fddd:1194:1194:1194::/64
			firewall-cmd --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
			firewall-cmd --permanent --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
		fi
	else
		# Create a service to set up persistent iptables rules
		iptables_path=$(command -v iptables)
		ip6tables_path=$(command -v ip6tables)
		# nf_tables is not available as standard in OVZ kernels. So use iptables-legacy
		# if we are in OVZ, with a nf_tables backend and iptables-legacy is available.
		if [[ $(systemd-detect-virt) == "openvz" ]] && readlink -f "$(command -v iptables)" | grep -q "nft" && hash iptables-legacy 2>/dev/null; then
			iptables_path=$(command -v iptables-legacy)
			ip6tables_path=$(command -v ip6tables-legacy)
		fi
		echo "[Unit]
Before=network.target
[Service]
Type=oneshot
ExecStart=$iptables_path -t nat -A POSTROUTING -s 10.69.1.0/24 ! -d 10.69.1.0/24 -j SNAT --to $ip
ExecStart=$iptables_path -I INPUT -p $protocol --dport $port -j ACCEPT
ExecStart=$iptables_path -I FORWARD -s 10.69.1.0/24 -j ACCEPT
ExecStart=$iptables_path -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$iptables_path -t nat -D POSTROUTING -s 10.69.1.0/24 ! -d 10.69.1.0/24 -j SNAT --to $ip
ExecStop=$iptables_path -D INPUT -p $protocol --dport $port -j ACCEPT
ExecStop=$iptables_path -D FORWARD -s 10.69.1.0/24 -j ACCEPT
ExecStop=$iptables_path -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" > /etc/systemd/system/openvpn-iptables.service
		if [[ -n "$ip6" ]]; then
			echo "ExecStart=$ip6tables_path -t nat -A POSTROUTING -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to $ip6
ExecStart=$ip6tables_path -I FORWARD -s fddd:1194:1194:1194::/64 -j ACCEPT
ExecStart=$ip6tables_path -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$ip6tables_path -t nat -D POSTROUTING -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to $ip6
ExecStop=$ip6tables_path -D FORWARD -s fddd:1194:1194:1194::/64 -j ACCEPT
ExecStop=$ip6tables_path -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" >> /etc/systemd/system/openvpn-iptables.service
		fi
		echo "RemainAfterExit=yes
[Install]
WantedBy=multi-user.target" >> /etc/systemd/system/openvpn-iptables.service
		systemctl enable --now openvpn-iptables.service
	fi
	# If SELinux is enabled and a custom port was selected, we need this
	if sestatus 2>/dev/null | grep "Current mode" | grep -q "enforcing" && [[ "$port" != 94 ]]; then
		# Install semanage if not already present
		if ! hash semanage 2>/dev/null; then
			if [[ "$os_version" -eq 7 ]]; then
				# Centos 7
				yum install -y policycoreutils-python
			else
				# CentOS 8 or Fedora
				dnf install -y policycoreutils-python-utils
			fi
		fi
		semanage port -a -t openvpn_port_t -p "$protocol" "$port"
	fi
	# If the server is behind NAT, use the correct IP address
	[[ -n "$public_ip" ]] && ip="$public_ip"
	# client-common.txt is created so we have a template to add further users later
	echo "client
dev tun
proto $protocol
remote $ip $port
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA512
cipher AES-256-CBC
ignore-unknown-option block-outside-dns
block-outside-dns
auth-user-pass
verb 3" > /etc/openvpn/server/client-common.txt
	# Enable and start the OpenVPN service
	systemctl enable --now openvpn-server@server.service
	# Generates the custom client.ovpn
	new_client
	echo
	echo "Finished!"
	echo
	echo "The client configuration is available in:" ~/"$client.ovpn"
	echo "New clients can be added by running this script again."
else
	clear
	echo "OpenVPN is already installed."
	echo
	echo "Select an option:"
	echo "   1) Add a new client"
	echo "   2) Revoke an existing client"
	echo "   3) Remove OpenVPN"
	echo "   4) Exit"
	read -p "Option: " option
	until [[ "$option" =~ ^[1-4]$ ]]; do
		echo "$option: invalid selection."
		read -p "Option: " option
	done
	case "$option" in
		1)
			echo
			echo "Provide a name for the client:"
			read -p "Name: " unsanitized_client
			client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
			while [[ -z "$client" || -e /etc/openvpn/server/easy-rsa/pki/issued/"$client".crt ]]; do
				echo "$client: invalid name."
				read -p "Name: " unsanitized_client
				client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
			done
			cd /etc/openvpn/server/easy-rsa/
			EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-client-full "$client" nopass
			# Generates the custom client.ovpn
			new_client
			echo
			echo "$client added. Configuration available in:" ~/"$client.ovpn"
			exit
		;;
		2)
			# This option could be documented a bit better and maybe even be simplified
			# ...but what can I say, I want some sleep too
			number_of_clients=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep -c "^V")
			if [[ "$number_of_clients" = 0 ]]; then
				echo
				echo "There are no existing clients!"
				exit
			fi
			echo
			echo "Select the client to revoke:"
			tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') '
			read -p "Client: " client_number
			until [[ "$client_number" =~ ^[0-9]+$ && "$client_number" -le "$number_of_clients" ]]; do
				echo "$client_number: invalid selection."
				read -p "Client: " client_number
			done
			client=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | sed -n "$client_number"p)
			echo
			read -p "Confirm $client revocation? [y/N]: " revoke
			until [[ "$revoke" =~ ^[yYnN]*$ ]]; do
				echo "$revoke: invalid selection."
				read -p "Confirm $client revocation? [y/N]: " revoke
			done
			if [[ "$revoke" =~ ^[yY]$ ]]; then
				cd /etc/openvpn/server/easy-rsa/
				./easyrsa --batch revoke "$client"
				EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
				rm -f /etc/openvpn/server/crl.pem
				cp /etc/openvpn/server/easy-rsa/pki/crl.pem /etc/openvpn/server/crl.pem
				# CRL is read with each client connection, when OpenVPN is dropped to nobody
				chown nobody:"$group_name" /etc/openvpn/server/crl.pem
				echo
				echo "$client revoked!"
			else
				echo
				echo "$client revocation aborted!"
			fi
			exit
		;;
		3)
			echo
			read -p "Confirm OpenVPN removal? [y/N]: " remove
			until [[ "$remove" =~ ^[yYnN]*$ ]]; do
				echo "$remove: invalid selection."
				read -p "Confirm OpenVPN removal? [y/N]: " remove
			done
			if [[ "$remove" =~ ^[yY]$ ]]; then
				port=$(grep '^port ' /etc/openvpn/server/server.conf | cut -d " " -f 2)
				protocol=$(grep '^proto ' /etc/openvpn/server/server.conf | cut -d " " -f 2)
				if systemctl is-active --quiet firewalld.service; then
					ip=$(firewall-cmd --direct --get-rules ipv4 nat POSTROUTING | grep '\-s 10.69.1.0/24 '"'"'!'"'"' -d 10.69.1.0/24' | grep -oE '[^ ]+$')
					# Using both permanent and not permanent rules to avoid a firewalld reload.
					firewall-cmd --remove-port="$port"/"$protocol"
					firewall-cmd --zone=trusted --remove-source=10.69.1.0/24
					firewall-cmd --permanent --remove-port="$port"/"$protocol"
					firewall-cmd --permanent --zone=trusted --remove-source=10.69.1.0/24
					firewall-cmd --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.69.1.0/24 ! -d 10.69.1.0/24 -j SNAT --to "$ip"
					firewall-cmd --permanent --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.69.1.0/24 ! -d 10.69.1.0/24 -j SNAT --to "$ip"
					if grep -qs "server-ipv6" /etc/openvpn/server/server.conf; then
						ip6=$(firewall-cmd --direct --get-rules ipv6 nat POSTROUTING | grep '\-s fddd:1194:1194:1194::/64 '"'"'!'"'"' -d fddd:1194:1194:1194::/64' | grep -oE '[^ ]+$')
						firewall-cmd --zone=trusted --remove-source=fddd:1194:1194:1194::/64
						firewall-cmd --permanent --zone=trusted --remove-source=fddd:1194:1194:1194::/64
						firewall-cmd --direct --remove-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
						firewall-cmd --permanent --direct --remove-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
					fi
				else
					systemctl disable --now openvpn-iptables.service
					rm -f /etc/systemd/system/openvpn-iptables.service
				fi
				if sestatus 2>/dev/null | grep "Current mode" | grep -q "enforcing" && [[ "$port" != 1194 ]]; then
					semanage port -d -t openvpn_port_t -p "$protocol" "$port"
				fi
				systemctl disable --now openvpn-server@server.service
				rm -f /etc/systemd/system/openvpn-server@server.service.d/disable-limitnproc.conf
				rm -f /etc/sysctl.d/99-openvpn-forward.conf
				if [[ "$os" = "debian" || "$os" = "ubuntu" ]]; then
					rm -rf /etc/openvpn/server
					apt-get remove --purge -y openvpn
				else
					# Else, OS must be CentOS or Fedora
					yum remove -y openvpn
					rm -rf /etc/openvpn/server
				fi
				echo
				echo "OpenVPN removed!"
			else
				echo
				echo "OpenVPN removal aborted!"
			fi
			exit
		;;
		4)
			exit
		;;
	esac
fi
systemctl restart openvpn
radiusConfig
}
####### NEW CODE #############
function checkans(){
	until [[ $ans =~ ^[y|n]+$ ]]; 
	do
        echo "Correct your answer! Do you have another RAS IP?[y/n]"
        read ans
		if [ "$ans" = "y" ] || [ "$ans" = "n" ];then
			g=1
		fi
	done
}
function radiusConfig(){
preinst
	packages=("openvpn-auth-radius" "build-essential" "libgcrypt20-dev" "unzip" "mlocate")
    for pkg in ${packages[@]}; do
        #is_pkg_installed=$(dpkg-query -W --showformat='${Status}\n' ${pkg} | grep "install ok installed" )
		is_pkg_installed=$( dpkg -s  ${pkg} | grep "install ok installed" )
		if [[ "$is_pkg_installed" == *"install ok installed"* ]]; then
			echo ${pkg} is installed.

        else
             apt install   ${pkg} -y
		fi
	done
	
	freeradius=/etc/radiusclient/radiusclient.conf
	if test -f "$freeradius"; then
        echo freeradius is installed.
    else
		wget https://github.com/FreeRADIUS/freeradius-client/archive/master.zip
		unzip master.zip
		mv freeradius-client-master freeradius-client
		cd freeradius-client
		./configure --prefix=/
		make && make install
		touch /etc/radiusclient/dictionary.microsoft 
			echo "# Microsoft’s VSA’s, from RFC 2548
#
# $Id: poptop_ads_howto_8.htm,v 1.8 2008/10/02 08:11:48 wskwok Exp $
#
VENDOR Microsoft 311 Microsoft
BEGIN VENDOR Microsoft
ATTRIBUTE MS-CHAP-Response 1 string Microsoft
ATTRIBUTE MS-CHAP-Error 2 string Microsoft
ATTRIBUTE MS-CHAP-CPW-1 3 string Microsoft
ATTRIBUTE MS-CHAP-CPW-2 4 string Microsoft
ATTRIBUTE MS-CHAP-LM-Enc-PW 5 string Microsoft
ATTRIBUTE MS-CHAP-NT-Enc-PW 6 string Microsoft
ATTRIBUTE MS-MPPE-Encryption-Policy 7 string Microsoft
# This is referred to as both singular and plural in the RFC.
# Plural seems to make more sense.
ATTRIBUTE MS-MPPE-Encryption-Type 8 string Microsoft
ATTRIBUTE MS-MPPE-Encryption-Types 8 string Microsoft
ATTRIBUTE MS-RAS-Vendor 9 integer Microsoft
ATTRIBUTE MS-CHAP-Domain 10 string Microsoft
ATTRIBUTE MS-CHAP-Challenge 11 string Microsoft
ATTRIBUTE MS-CHAP-MPPE-Keys 12 string Microsoft encrypt=1
ATTRIBUTE MS-BAP-Usage 13 integer Microsoft
ATTRIBUTE MS-Link-Utilization-Threshold 14 integer Microsoft
ATTRIBUTE MS-Link-Drop-Time-Limit 15 integer Microsoft
ATTRIBUTE MS-MPPE-Send-Key 16 string Microsoft
ATTRIBUTE MS-MPPE-Recv-Key 17 string Microsoft
ATTRIBUTE MS-RAS-Version 18 string Microsoft
ATTRIBUTE MS-Old-ARAP-Password 19 string Microsoft
ATTRIBUTE MS-New-ARAP-Password 20 string Microsoft
ATTRIBUTE MS-ARAP-PW-Change-Reason 21 integer Microsoft
ATTRIBUTE MS-Filter 22 string Microsoft
ATTRIBUTE MS-Acct-Auth-Type 23 integer Microsoft
ATTRIBUTE MS-Acct-EAP-Type 24 integer Microsoft
ATTRIBUTE MS-CHAP2-Response 25 string Microsoft
ATTRIBUTE MS-CHAP2-Success 26 string Microsoft
ATTRIBUTE MS-CHAP2-CPW 27 string Microsoft
ATTRIBUTE MS-Primary-DNS-Server 28 ipaddr
ATTRIBUTE MS-Secondary-DNS-Server 29 ipaddr
ATTRIBUTE MS-Primary-NBNS-Server 30 ipaddr Microsoft
ATTRIBUTE MS-Secondary-NBNS-Server 31 ipaddr Microsoft
#ATTRIBUTE MS-ARAP-Challenge 33 string Microsoft
#
# Integer Translations
#
# MS-BAP-Usage Values
VALUE MS-BAP-Usage Not-Allowed 0
VALUE MS-BAP-Usage Allowed 1
VALUE MS-BAP-Usage Required 2
# MS-ARAP-Password-Change-Reason Values
VALUE MS-ARAP-PW-Change-Reason Just-Change-Password 1
VALUE MS-ARAP-PW-Change-Reason Expired-Password 2
VALUE MS-ARAP-PW-Change-Reason Admin-Requires-Password-Change 3
VALUE MS-ARAP-PW-Change-Reason Password-Too-Short 4
# MS-Acct-Auth-Type Values
VALUE MS-Acct-Auth-Type PAP 1
VALUE MS-Acct-Auth-Type CHAP 2
VALUE MS-Acct-Auth-Type MS-CHAP-1 3
VALUE MS-Acct-Auth-Type MS-CHAP-2 4
VALUE MS-Acct-Auth-Type EAP 5
# MS-Acct-EAP-Type Values
VALUE MS-Acct-EAP-Type MD5 4
VALUE MS-Acct-EAP-Type OTP 5
VALUE MS-Acct-EAP-Type Generic-Token-Card 6
VALUE MS-Acct-EAP-Type TLS 13
END-VENDOR Microsoft" | tee /etc/radiusclient/dictionary.microsoft
sed -i -r '/.*ATTRIBUTE.*NAS-IPv6-Address.*/s/^/#/g' /etc/radiusclient/dictionary
sed -i -r '/.*ATTRIBUTE.*Framed-IPv6-Prefix.*/s/^/#/g' /etc/radiusclient/dictionary
sed -i -r '/.*ATTRIBUTE.*Login-IPv6-Host.*/s/^/#/g' /etc/radiusclient/dictionary
sed -i -r '/.*ATTRIBUTE.*Framed-IPv6-Pool.*/s/^/#/g' /etc/radiusclient/dictionary
sed -i -r '/.*ATTRIBUTE.*Framed-IPv6-Address.*/s/^/#/g' /etc/radiusclient/dictionary
sed -i -r '/.*ATTRIBUTE.*DNS-Server-IPv6-Address.*/s/^/#/g' /etc/radiusclient/dictionary
sed -i -r '/.*ATTRIBUTE.*Route-IPv6-Information.*/s/^/#/g' /etc/radiusclient/dictionary
sed -i -r '/.*ATTRIBUTE.*Framed-Interface-Id.*/s/^/#/g' /etc/radiusclient/dictionary
sed -i -r '/.*ATTRIBUTE.*Framed-IPv6-Rout.*/s/^/#/g' /etc/radiusclient/dictionary
sed -i -e '$a INCLUDE /etc/radiusclient/dictionary.merit' /etc/radiusclient/dictionary
sed -i -e '$a INCLUDE /etc/radiusclient/dictionary.microsoft' /etc/radiusclient/dictionary
sed -i '/issue.*issue/a seqfile \/var\/run\/freeradius\/freeradius.pid' /etc/radiusclient/radiusclient.conf
sed -i -r '/^radius_deadtime/s/^/#/g' /etc/radiusclient/radiusclient.conf #comment
sed -i '/.*net.ipv4.ip.*/s/^#//g' /etc/sysctl.conf
mkdir /var/run/freeradius
sysctl -p
systemctl restart openvpn
        fi

	 sed -e '/^acctserver.*localhost/s/^/#/' -i -r /etc/radiusclient/radiusclient.conf #comment
	 sed -e '/^authserver.*localhost/s/^/#/' -i -r /etc/radiusclient/radiusclient.conf #comment
	 clear
	cat /etc/radiusclient/radiusclient.conf | grep -o '^authserver.*\|^acc.*\|^securepass.*'
	f=0
	g=0
	while [ $f -eq 0 ];do
		if [ "$g" = 0 ]; then
		echo "Do you have another RAS IP?[y/n]"
        read ans
		fi

        if [ "$ans" = "y" ]
	
        then
          read -rp "Please Enter IBSng IP Address: " IPBS
          read -rp "Please Enter SecurePass: " secpass
		  echo "$IPBS	$secpass" |  tee /etc/radiusclient/servers
          sed -i -r "/.*simply.*/a authserver   $IPBS"  /etc/radiusclient/radiusclient.conf
          sed -i -r "/.*for authserver applies.*/a acctserver   $IPBS" /etc/radiusclient/radiusclient.conf
          echo "Add Successfully"
		sleep 1
echo -e "
NAS-Identifier=OpenVpn
Service-Type=5
Framed-Protocol=1
NAS-Port-Type=5
NAS-IP-Address=$IP
OpenVPNConfig=/etc/openvpn/server/server.conf
subnet=255.255.255.0
overwriteccfiles=true
server
{
acctport=1813
authport=1812
name=$IPBS
retry=1
wait=1
sharedsecret=$secpass
}" >> /usr/lib/openvpn/radiusplugin.cnf
		systemctl restart openvpn
		g=0
		elif [ "$ans" = "n" ]; then
			 f=1
		else
			 checkans
		fi
        
	done

}
 function addras(){
	clear
	cat /etc/radiusclient/radiusclient.conf | grep -o '^authserver.*\|^acc.*\|^securepass.*'
	f=0
	g=0
	while [ $f -eq 0 ];do
		if [ "$g" = 0 ]; then
		echo "Do you have another RAS IP?[y/n]"
        read ans
		fi

        if [ "$ans" = "y" ]
	
        then
          read -rp "Please Enter IBSng IP Address: " IPBS
          read -rp "Please Enter SecurePass: " secpass
		  echo "$IPBS	$secpass" |  tee /etc/radiusclient/servers
          sed -i -r "/.*simply.*/a authserver   $IPBS"  /etc/radiusclient/radiusclient.conf
          sed -i -r "/.*for authserver applies.*/a acctserver   $IPBS" /etc/radiusclient/radiusclient.conf
          echo "Add Successfully"
		sleep 1
		echo -e "
	NAS-Identifier=OpenVpn
	Service-Type=5
	Framed-Protocol=1
	NAS-Port-Type=5
	NAS-IP-Address=$IP
	OpenVPNConfig=/etc/openvpn/server/server.conf
	subnet=255.255.255.0
	overwriteccfiles=true
	server
	{
		acctport=1813
		authport=1812
		name=$IPBS
		retry=1
		wait=1
		sharedsecret=$secpass
	}" >> /usr/lib/openvpn/radiusplugin.cnf
		systemctl restart openvpn
		g=0
		elif [ "$ans" = "n" ]; then
			 f=1
		else
			 checkans
		fi
        
	done
}
function editras(){
	clear
	cat /etc/radiusclient/radiusclient.conf | grep -o '^authserver.*\|^acc.*\|^securepass.*'
	read -rp "Please enter new RAS IP: " newrasip
	read -rp "Now please enter new Secret: " newsecret
	sed -i -r "s/authserver.*/authserver   $newrasip/g"  /etc/radiusclient/radiusclient.conf
	sed -i -r "s/acctserver.*/acctserver   $newrasip/g" /etc/radiusclient/radiusclient.conf
	sed -i -r "s/sharedsecret=.*/sharedsecret=$newsecret/g" /usr/lib/openvpn/radiusplugin.cnf
	sed -i -r "s/name=.*/name=$newrasip/g" /usr/lib/openvpn/radiusplugin.cnf
	echo "$newrasip	$newsecret" |  tee /etc/radiusclient/servers
	sleep 3
	}
function preinst(){
ufw disable
apt update && apt dist-upgrade -y && apt autoremove -y
}
function installocs(){
preinst
echo installing...
apt update -qq ; apt install ocserv certbot -y
clear
read -rp "Please Enter Domain For ocserv SSL: " ocdomain
read -rp "Please Enter Email For ocserv SSL: " ocmail
certbot certonly --standalone --preferred-challenges http --agree-tos --email $ocmail -d $ocdomain
sed -i -r '/^auth = "pam\[.*/s/^/#/g' /etc/ocserv/ocserv.conf #comment
sed -i -r '/.*auth = "radius\[.*/s/^#//g' /etc/ocserv/ocserv.conf #uncomment
sed -i -r '/^route = .*/s/^/#/g' /etc/ocserv/ocserv.conf  #comment
sed -i    '/.*route = default.*/s/^#//g' /etc/ocserv/ocserv.conf #uncomment
sed -i -r '/^server-key/s/^/#/g' /etc/ocserv/ocserv.conf #comment
sed -i -r '/^server-cert/s/^/#/g' /etc/ocserv/ocserv.conf #comment
sed -i -r "/.*socket-file.*/a server-key = /etc/letsencrypt/live/$ocdomain/privkey.pem"  /etc/ocserv/ocserv.conf
sed -i -r "/.*socket-file.*/a server-cert = /etc/letsencrypt/live/$ocdomain/fullchain.pem"  /etc/ocserv/ocserv.conf
sed -i -r "s/ipv4-network.*/ipv4-network = 10.69.2.0/g" /etc/ocserv/ocserv.conf
sed -i -r "s/ipv4-netmask.*/ipv4-netmask = 255.255.255.0/g" /etc/ocserv/ocserv.conf
systemctl restart ocserv
iptablesserv
radiusConfig
systemctl restart ocserv
}
function installl2tp(){
preinst
read -rp "Please Enter IPSec_PSK: " YOUR_IPSEC_PSK
YOUR_IPSEC_PSK=$YOUR_IPSEC_PSK
# =====================================================

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
SYS_DT=$(date +%F-%T | tr ':' '_')

exiterr()  { echo "Error: $1" >&2; exit 1; }
exiterr2() { exiterr "'apt-get install' failed."; }
conf_bk() { /bin/cp -f "$1" "$1.old-$SYS_DT" 2>/dev/null; }
bigecho() { echo "## $1"; }

check_ip() {
  IP_REGEX='^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'
  printf '%s' "$1" | tr -d '\n' | grep -Eq "$IP_REGEX"

}

check_root() {
  if [ "$(id -u)" != 0 ]; then
    exiterr "Script must be run as root. Try ' bash $0'"
  fi
}

check_vz() {
  if [ -f /proc/user_beancounters ]; then
    exiterr "OpenVZ VPS is not supported."
  fi
}

check_os() {
  os_type=$(lsb_release -si 2>/dev/null)
  os_arch=$(uname -m | tr -dc 'A-Za-z0-9_-')
  [ -z "$os_type" ] && [ -f /etc/os-release ] && os_type=$(. /etc/os-release && printf '%s' "$ID")
  case $os_type in
    [Uu]buntu)
      os_type=ubuntu
      ;;
    [Dd]ebian)
      os_type=debian
      ;;
    [Rr]aspbian)
      os_type=raspbian
      ;;
    *)
      exiterr "This script only supports Ubuntu and Debian."
      ;;
  esac
  os_ver=$(sed 's/\..*//' /etc/debian_version | tr -dc 'A-Za-z0-9')
  if [ "$os_ver" = "8" ] || [ "$os_ver" = "jessiesid" ]; then
    exiterr "Debian 8 or Ubuntu < 16.04 is not supported."
  fi
}

check_iface() {
  def_iface=$(route 2>/dev/null | grep -m 1 '^default' | grep -o '[^ ]*$')
  [ -z "$def_iface" ] && def_iface=$(ip -4 route list 0/0 2>/dev/null | grep -m 1 -Po '(?<=dev )(\S+)')
  def_state=$(cat "/sys/class/net/$def_iface/operstate" 2>/dev/null)
  if [ -n "$def_state" ] && [ "$def_state" != "down" ]; then
    if ! uname -m | grep -qi -e '^arm' -e '^aarch64'; then
      case $def_iface in
        wl*)
          exiterr "Wireless interface '$def_iface' detected. DO NOT run this script on your PC or Mac!"
          ;;
      esac
    fi
    NET_IFACE="$def_iface"
  else
    eth0_state=$(cat "/sys/class/net/eth0/operstate" 2>/dev/null)
    if [ -z "$eth0_state" ] || [ "$eth0_state" = "down" ]; then
      exiterr "Could not detect the default network interface."
    fi
    NET_IFACE=eth0
  fi
}

check_creds() {
  [ -n "$YOUR_IPSEC_PSK" ] && VPN_IPSEC_PSK="$YOUR_IPSEC_PSK"

  if [ -z "$VPN_IPSEC_PSK" ] ; then
    bigecho "VPN credentials not set by user. Generating random PSK and password..."
    VPN_IPSEC_PSK=$(LC_CTYPE=C tr -dc 'A-HJ-NPR-Za-km-z2-9' </dev/urandom 2>/dev/null | head -c 20)
  fi

  if [ -z "$VPN_IPSEC_PSK" ] ; then
    exiterr "All VPN credentials must be specified. Edit the script and re-enter them."
  fi

  if printf '%s' "$VPN_IPSEC_PSK" | LC_ALL=C grep -q '[^ -~]\+'; then
    exiterr "VPN credentials must not contain non-ASCII characters."
  fi

  case "$VPN_IPSEC_PSK" in
    *[\\\"\']*)
      exiterr "VPN credentials must not contain these special characters: \\ \" '"
      ;;
  esac
}

check_dns() {
  if { [ -n "$VPN_DNS_SRV1" ] && ! check_ip "$VPN_DNS_SRV1"; } \
    || { [ -n "$VPN_DNS_SRV2" ] && ! check_ip "$VPN_DNS_SRV2"; } then
    exiterr "The DNS server specified is invalid."
  fi
}

check_iptables() {
  if [ -x /sbin/iptables ] && ! iptables -nL INPUT >/dev/null 2>&1; then
    exiterr "IPTables check failed. Reboot and re-run this script."
  fi
}

start_setup() {
  bigecho "VPN setup in progress... Please be patient."
  # shellcheck disable=SC2154
  trap 'dlo=$dl;dl=$LINENO' DEBUG 2>/dev/null
  trap 'finish $? $((dlo+1))' EXIT
  mkdir -p /opt/src
  cd /opt/src || exit 1
}

wait_for_apt() {
  count=0
  apt_lk=/var/lib/apt/lists/lock
  pkg_lk=/var/lib/dpkg/lock
  while fuser "$apt_lk" "$pkg_lk" >/dev/null 2>&1 \
    || lsof "$apt_lk" >/dev/null 2>&1 || lsof "$pkg_lk" >/dev/null 2>&1; do
    [ "$count" = "0" ] && echo "## Waiting for apt to be available..."
    [ "$count" -ge "100" ] && exiterr "Could not get apt/dpkg lock."
    count=$((count+1))
    printf '%s' '.'
    sleep 3
  done
}

update_apt_cache() {
  bigecho "Installing packages required for setup..."
  export DEBIAN_FRONTEND=noninteractive
  (
    set -x
    apt-get -yqq update
  ) || exiterr "'apt-get update' failed."
}

install_setup_pkgs() {
  (
    set -x
    apt-get -yqq install wget dnsutils openssl \
      iptables iproute2 gawk grep sed net-tools >/dev/null
  ) || exiterr2
}

detect_ip() {
  bigecho "Trying to auto discover IP of this server..."
  public_ip=${VPN_PUBLIC_IP:-''}
  check_ip "$public_ip" || public_ip=$(curl -s https://api.ipify.org)
  check_ip "$public_ip" || exiterr "Cannot detect this server's public IP. Define it as variable 'VPN_PUBLIC_IP' and re-run this script."
}

install_vpn_pkgs() {
  bigecho "Installing packages required for the VPN..."
  (
    set -x
    apt-get -yqq install libnss3-dev libnspr4-dev pkg-config \
      libpam0g-dev libcap-ng-dev libcap-ng-utils libselinux1-dev \
      libcurl4-nss-dev flex bison gcc make libnss3-tools \
      libevent-dev libsystemd-dev uuid-runtime ppp xl2tpd >/dev/null
  ) || exiterr2
}

install_fail2ban() {
  bigecho "Installing Fail2Ban to protect SSH..."
  (
    set -x
    apt-get -yqq install fail2ban >/dev/null
  ) || exiterr2
}

get_ikev2_script() {
  bigecho "Downloading IKEv2 script..."
  ikev2_url="https://github.com/hwdsl2/setup-ipsec-vpn/raw/master/extras/ikev2setup.sh"
  (
    set -x
    wget -t 3 -T 30 -q -O ikev2.sh "$ikev2_url"
  ) || /bin/rm -f ikev2.sh
  [ -s ikev2.sh ] && chmod +x ikev2.sh && ln -s /opt/src/ikev2.sh /usr/bin 2>/dev/null
}

check_libreswan() {
  SWAN_VER=4.5
  ipsec_ver=$(/usr/local/sbin/ipsec --version 2>/dev/null)
  swan_ver_old=$(printf '%s' "$ipsec_ver" | sed -e 's/.*Libreswan U\?//' -e 's/\( (\|\/K\).*//')
  [ "$swan_ver_old" = "$SWAN_VER" ]
}

get_libreswan() {
  if ! check_libreswan; then
    bigecho "Downloading Libreswan..."
    swan_file="libreswan-$SWAN_VER.tar.gz"
    swan_url1="https://github.com/libreswan/libreswan/archive/v$SWAN_VER.tar.gz"
    swan_url2="https://download.libreswan.org/$swan_file"
    (
      set -x
      wget -t 3 -T 30 -q -O "$swan_file" "$swan_url1" || wget -t 3 -T 30 -q -O "$swan_file" "$swan_url2"
    ) || exit 1
    /bin/rm -rf "/opt/src/libreswan-$SWAN_VER"
    tar xzf "$swan_file" && /bin/rm -f "$swan_file"
  else
    bigecho "Libreswan $SWAN_VER is already installed, skipping..."
  fi
}

install_libreswan() {
  if ! check_libreswan; then
    bigecho "Compiling and installing Libreswan, please wait..."
    cd "libreswan-$SWAN_VER" || exit 1
cat > Makefile.inc.local <<'EOF'
WERROR_CFLAGS=-w -s
USE_DNSSEC=false
USE_DH2=true
USE_NSS_KDF=false
FINALNSSDIR=/etc/ipsec.d
EOF
    if ! grep -qs 'VERSION_CODENAME=' /etc/os-release; then
cat >> Makefile.inc.local <<'EOF'
USE_DH31=false
USE_NSS_AVA_COPY=true
USE_NSS_IPSEC_PROFILE=false
USE_GLIBC_KERN_FLIP_HEADERS=true
EOF
    fi
    if ! grep -qs IFLA_XFRM_LINK /usr/include/linux/if_link.h; then
      echo "USE_XFRM_INTERFACE_IFLA_HEADER=true" >> Makefile.inc.local
    fi
    NPROCS=$(grep -c ^processor /proc/cpuinfo)
    [ -z "$NPROCS" ] && NPROCS=1
    (
      set -x
      make "-j$((NPROCS+1))" -s base >/dev/null && make -s install-base >/dev/null
    )

    cd /opt/src || exit 1
    /bin/rm -rf "/opt/src/libreswan-$SWAN_VER"
    if ! /usr/local/sbin/ipsec --version 2>/dev/null | grep -qF "$SWAN_VER"; then
      exiterr "Libreswan $SWAN_VER failed to build."
    fi
  fi
}

create_vpn_config() {
  bigecho "Creating VPN configuration..."

  L2TP_NET=${VPN_L2TP_NET:-'10.69.3.0/24'}
  L2TP_LOCAL=${VPN_L2TP_LOCAL:-'10.69.3.1'}
  L2TP_POOL=${VPN_L2TP_POOL:-'10.69.3.10-10.69.3.250'}
  XAUTH_NET=${VPN_XAUTH_NET:-'10.69.5.0/24'}
  XAUTH_POOL=${VPN_XAUTH_POOL:-'10.69.5.10-10.69.5.250'}
  DNS_SRV1=${VPN_DNS_SRV1:-'8.8.8.8'}
  DNS_SRV2=${VPN_DNS_SRV2:-'8.8.4.4'}
  DNS_SRVS="\"$DNS_SRV1 $DNS_SRV2\""
  [ -n "$VPN_DNS_SRV1" ] && [ -z "$VPN_DNS_SRV2" ] && DNS_SRVS="$DNS_SRV1"

  # Create IPsec config
  conf_bk "/etc/ipsec.conf"
cat > /etc/ipsec.conf <<EOF
version 2.0

config setup
  virtual-private=%v4:10.0.0.0/8,%v4:192.168.0.0/16,%v4:172.16.0.0/12,%v4:!$L2TP_NET,%v4:!$XAUTH_NET
  uniqueids=no

conn shared
  left=%defaultroute
  leftid=$public_ip
  right=%any
  encapsulation=yes
  authby=secret
  pfs=no
  rekey=no
  keyingtries=5
  dpddelay=30
  dpdtimeout=120
  dpdaction=clear
  ikev2=never
  ike=aes256-sha2,aes128-sha2,aes256-sha1,aes128-sha1,aes256-sha2;modp1024,aes128-sha1;modp1024
  phase2alg=aes_gcm-null,aes128-sha1,aes256-sha1,aes256-sha2_512,aes128-sha2,aes256-sha2
  ikelifetime=24h
  salifetime=24h
  sha2-truncbug=no

conn l2tp-psk
  auto=add
  leftprotoport=17/1701
  rightprotoport=17/%any
  type=transport
  also=shared

conn xauth-psk
  auto=add
  leftsubnet=0.0.0.0/0
  rightaddresspool=$XAUTH_POOL
  modecfgdns=$DNS_SRVS
  leftxauthserver=yes
  rightxauthclient=yes
  leftmodecfgserver=yes
  rightmodecfgclient=yes
  modecfgpull=yes
  cisco-unity=yes
  also=shared

include /etc/ipsec.d/*.conf
EOF

  if uname -m | grep -qi '^arm'; then
    if ! modprobe -q sha512; then
      sed -i '/phase2alg/s/,aes256-sha2_512//' /etc/ipsec.conf
    fi
  fi

  # Specify IPsec PSK
  conf_bk "/etc/ipsec.secrets"
cat > /etc/ipsec.secrets <<EOF
%any  %any  : PSK "$VPN_IPSEC_PSK"
EOF

  # Create xl2tpd config
  conf_bk "/etc/xl2tpd/xl2tpd.conf"
cat > /etc/xl2tpd/xl2tpd.conf <<EOF
[global]
port = 1701

[lns default]
ip range = $L2TP_POOL
local ip = $L2TP_LOCAL
require chap = yes
refuse pap = yes
require authentication = yes
name = l2tpd
pppoptfile = /etc/ppp/options.xl2tpd
length bit = yes
EOF

  # Set xl2tpd options
  conf_bk "/etc/ppp/options.xl2tpd"
cat > /etc/ppp/options.xl2tpd <<EOF
+mschap-v2
ipcp-accept-local
ipcp-accept-remote
noccp
auth
mtu 1280
mru 1280
proxyarp
lcp-echo-failure 4
lcp-echo-interval 30
connect-delay 5000
ms-dns $DNS_SRV1
EOF

  if [ -z "$VPN_DNS_SRV1" ] || [ -n "$VPN_DNS_SRV2" ]; then
cat >> /etc/ppp/options.xl2tpd <<EOF
ms-dns $DNS_SRV2
EOF
  fi
}


update_sysctl() {
  bigecho "Updating sysctl settings..."
  if ! grep -qs "hwdsl2 VPN script" /etc/sysctl.conf; then
    conf_bk "/etc/sysctl.conf"
cat >> /etc/sysctl.conf <<EOF

# Added by hwdsl2 VPN script
kernel.msgmnb = 65536
kernel.msgmax = 65536

net.ipv4.ip_forward = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.default.rp_filter = 0
net.ipv4.conf.$NET_IFACE.send_redirects = 0
net.ipv4.conf.$NET_IFACE.rp_filter = 0

net.core.wmem_max = 12582912
net.core.rmem_max = 12582912
net.ipv4.tcp_rmem = 10240 87380 12582912
net.ipv4.tcp_wmem = 10240 87380 12582912
EOF
  fi
}


check_swan_ver() {
  swan_ver_url="https://dl.ls20.com/v1/$os_type/$os_ver/swanver?arch=$os_arch&ver=$SWAN_VER"
  [ "$1" != "0" ] && swan_ver_url="$swan_ver_url&e=$2"
  swan_ver_latest=$(wget -t 3 -T 15 -qO- "$swan_ver_url")
  if printf '%s' "$swan_ver_latest" | grep -Eq '^([3-9]|[1-9][0-9]{1,2})(\.([0-9]|[1-9][0-9]{1,2})){1,2}$' \
    && [ "$1" = "0" ] && [ -n "$SWAN_VER" ] && [ "$SWAN_VER" != "$swan_ver_latest" ] \
    && printf '%s\n%s' "$SWAN_VER" "$swan_ver_latest" | sort -C -V; then
cat <<EOF
Note: A newer version of Libreswan ($swan_ver_latest) is available.
      To update, run:
      wget https://git.io/vpnupgrade -O vpnup.sh &&  sh vpnup.sh

EOF
  fi
}

finish() {
  check_swan_ver "$1" "$2"
  exit "$1"
}

vpnsetup() {
  check_root
  check_vz
  check_os
  check_iface
  check_creds
  check_dns
  check_iptables
  start_setup
  wait_for_apt
  update_apt_cache
  install_setup_pkgs
  detect_ip
  install_vpn_pkgs
  install_fail2ban
  get_ikev2_script
  get_libreswan
  install_libreswan
  create_vpn_config
  update_sysctl
  start_services
}

## Defer setup until we have the complete script
vpnsetup "$@"
mkdir /etc/ipsec.d/
echo -e "plugin /usr/lib/pppd/2.4.7/radius.so\nplugin /usr/lib/pppd/2.4.7/radattr.so" |  tee -a /etc/ppp/options.xl2tpd
systemctl restart xl2tpd ipsec
systemctl restart ipsec.service
iptablesserv
radiusConfig
systemctl restart xl2tpd
}
function installpptp(){
preinst
echo "Installing..."
apt update -qq ; apt install pptpd build-essential libgcrypt20-dev -y
echo -e "localip 10.69.4.1\nremoteip 10.69.4.5-250" |  tee -a /etc/pptpd.conf
echo -e "ms-dns 8.8.8.8\nms-dns 9.9.9.9\nplugin /usr/lib/pppd/2.4.7/radius.so\nplugin /usr/lib/pppd/2.4.7/radattr.so" |  tee -a /etc/ppp/pptpd-options
echo 'net.ipv4.ip_forward=1' >/etc/sysctl.d/99-openvpn.conf
sysctl --system
systemctl enable pptpd
systemctl start pptpd
iptablesserv
radiusConfig
systemctl restart pptpd
}

function installsocks5(){
preinst
#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH
#
# Auto install Shadowsocks Server (all version)
#
# Copyright (C) 2016-2019 Teddysun <i@teddysun.com>
#
# System Required:  CentOS 6+, Debian7+, Ubuntu12+
#
# Reference URL:
# https://github.com/shadowsocks/shadowsocks
# https://github.com/shadowsocks/shadowsocks-go
# https://github.com/shadowsocks/shadowsocks-libev
# https://github.com/shadowsocks/shadowsocks-windows
# https://github.com/shadowsocksr-rm/shadowsocksr
# https://github.com/shadowsocksrr/shadowsocksr
# https://github.com/shadowsocksrr/shadowsocksr-csharp
#
# Thanks:
# @clowwindy  <https://twitter.com/clowwindy>
# @breakwa11  <https://twitter.com/breakwa11>
# @cyfdecyf   <https://twitter.com/cyfdecyf>
# @madeye     <https://github.com/madeye>
# @linusyang  <https://github.com/linusyang>
# @Akkariiin  <https://github.com/Akkariiin>
# 
# Intro:  https://teddysun.com/486.html

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'

[[ $EUID -ne 0 ]] && echo -e "[${red}Error${plain}] This script must be run as root!" && exit 1

cur_dir=$( pwd )
software=(Shadowsocks-Python ShadowsocksR Shadowsocks-Go Shadowsocks-libev)

libsodium_file="libsodium-1.0.17"
libsodium_url="https://github.com/jedisct1/libsodium/releases/download/1.0.17/libsodium-1.0.17.tar.gz"

mbedtls_file="mbedtls-2.16.0"
mbedtls_url="https://tls.mbed.org/download/mbedtls-2.16.0-gpl.tgz"

shadowsocks_python_file="shadowsocks-master"
shadowsocks_python_url="https://github.com/shadowsocks/shadowsocks/archive/master.zip"
shadowsocks_python_init="/etc/init.d/shadowsocks-python"
shadowsocks_python_config="/etc/shadowsocks-python/config.json"
shadowsocks_python_centos="https://raw.githubusercontent.com/teddysun/shadowsocks_install/master/shadowsocks"
shadowsocks_python_debian="https://raw.githubusercontent.com/teddysun/shadowsocks_install/master/shadowsocks-debian"

shadowsocks_r_file="shadowsocksr-3.2.2"
shadowsocks_r_url="https://github.com/shadowsocksrr/shadowsocksr/archive/3.2.2.tar.gz"
shadowsocks_r_init="/etc/init.d/shadowsocks-r"
shadowsocks_r_config="/etc/shadowsocks-r/config.json"
shadowsocks_r_centos="https://raw.githubusercontent.com/teddysun/shadowsocks_install/master/shadowsocksR"
shadowsocks_r_debian="https://raw.githubusercontent.com/teddysun/shadowsocks_install/master/shadowsocksR-debian"

shadowsocks_go_file_64="shadowsocks-server-linux64-1.2.2"
shadowsocks_go_url_64="https://dl.lamp.sh/shadowsocks/shadowsocks-server-linux64-1.2.2.gz"
shadowsocks_go_file_32="shadowsocks-server-linux32-1.2.2"
shadowsocks_go_url_32="https://dl.lamp.sh/shadowsocks/shadowsocks-server-linux32-1.2.2.gz"
shadowsocks_go_init="/etc/init.d/shadowsocks-go"
shadowsocks_go_config="/etc/shadowsocks-go/config.json"
shadowsocks_go_centos="https://raw.githubusercontent.com/teddysun/shadowsocks_install/master/shadowsocks-go"
shadowsocks_go_debian="https://raw.githubusercontent.com/teddysun/shadowsocks_install/master/shadowsocks-go-debian"

shadowsocks_libev_init="/etc/init.d/shadowsocks-libev"
shadowsocks_libev_config="/etc/shadowsocks-libev/config.json"
shadowsocks_libev_centos="https://raw.githubusercontent.com/teddysun/shadowsocks_install/master/shadowsocks-libev"
shadowsocks_libev_debian="https://raw.githubusercontent.com/teddysun/shadowsocks_install/master/shadowsocks-libev-debian"

# Stream Ciphers
common_ciphers=(
aes-256-gcm
aes-192-gcm
aes-128-gcm
aes-256-ctr
aes-192-ctr
aes-128-ctr
aes-256-cfb
aes-192-cfb
aes-128-cfb
camellia-128-cfb
camellia-192-cfb
camellia-256-cfb
xchacha20-ietf-poly1305
chacha20-ietf-poly1305
chacha20-ietf
chacha20
salsa20
rc4-md5
)
go_ciphers=(
aes-256-cfb
aes-192-cfb
aes-128-cfb
aes-256-ctr
aes-192-ctr
aes-128-ctr
chacha20-ietf
chacha20
salsa20
rc4-md5
)
r_ciphers=(
none
aes-256-cfb
aes-192-cfb
aes-128-cfb
aes-256-cfb8
aes-192-cfb8
aes-128-cfb8
aes-256-ctr
aes-192-ctr
aes-128-ctr
chacha20-ietf
chacha20
salsa20
xchacha20
xsalsa20
rc4-md5
)
# Reference URL:
# https://github.com/shadowsocksr-rm/shadowsocks-rss/blob/master/ssr.md
# https://github.com/shadowsocksrr/shadowsocksr/commit/a3cf0254508992b7126ab1151df0c2f10bf82680
# Protocol
protocols=(
origin
verify_deflate
auth_sha1_v4
auth_sha1_v4_compatible
auth_aes128_md5
auth_aes128_sha1
auth_chain_a
auth_chain_b
auth_chain_c
auth_chain_d
auth_chain_e
auth_chain_f
)
# obfs
obfs=(
plain
http_simple
http_simple_compatible
http_post
http_post_compatible
tls1.2_ticket_auth
tls1.2_ticket_auth_compatible
tls1.2_ticket_fastauth
tls1.2_ticket_fastauth_compatible
)
# libev obfuscating
obfs_libev=(http tls)
# initialization parameter
libev_obfs=""

disable_selinux(){
    if [ -s /etc/selinux/config ] && grep 'SELINUX=enforcing' /etc/selinux/config; then
        sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
        setenforce 0
    fi
}

check_sys(){
    local checkType=$1
    local value=$2

    local release=''
    local systemPackage=''

    if [[ -f /etc/redhat-release ]]; then
        release="centos"
        systemPackage="yum"
    elif grep -Eqi "debian|raspbian" /etc/issue; then
        release="debian"
        systemPackage="apt"
    elif grep -Eqi "ubuntu" /etc/issue; then
        release="ubuntu"
        systemPackage="apt"
    elif grep -Eqi "centos|red hat|redhat" /etc/issue; then
        release="centos"
        systemPackage="yum"
    elif grep -Eqi "debian|raspbian" /proc/version; then
        release="debian"
        systemPackage="apt"
    elif grep -Eqi "ubuntu" /proc/version; then
        release="ubuntu"
        systemPackage="apt"
    elif grep -Eqi "centos|red hat|redhat" /proc/version; then
        release="centos"
        systemPackage="yum"
    fi

    if [[ "${checkType}" == "sysRelease" ]]; then
        if [ "${value}" == "${release}" ]; then
            return 0
        else
            return 1
        fi
    elif [[ "${checkType}" == "packageManager" ]]; then
        if [ "${value}" == "${systemPackage}" ]; then
            return 0
        else
            return 1
        fi
    fi
}

version_ge(){
    test "$(echo "$@" | tr " " "\n" | sort -rV | head -n 1)" == "$1"
}

version_gt(){
    test "$(echo "$@" | tr " " "\n" | sort -V | head -n 1)" != "$1"
}

check_kernel_version(){
    local kernel_version=$(uname -r | cut -d- -f1)
    if version_gt ${kernel_version} 3.7.0; then
        return 0
    else
        return 1
    fi
}

check_kernel_headers(){
    if check_sys packageManager yum; then
        if rpm -qa | grep -q headers-$(uname -r); then
            return 0
        else
            return 1
        fi
    elif check_sys packageManager apt; then
        if dpkg -s linux-headers-$(uname -r) > /dev/null 2>&1; then
            return 0
        else
            return 1
        fi
    fi
    return 1
}

getversion(){
    if [[ -s /etc/redhat-release ]]; then
        grep -oE  "[0-9.]+" /etc/redhat-release
    else
        grep -oE  "[0-9.]+" /etc/issue
    fi
}

centosversion(){
    if check_sys sysRelease centos; then
        local code=$1
        local version="$(getversion)"
        local main_ver=${version%%.*}
        if [ "$main_ver" == "$code" ]; then
            return 0
        else
            return 1
        fi
    else
        return 1
    fi
}

autoconf_version(){
    if [ ! "$(command -v autoconf)" ]; then
        echo -e "[${green}Info${plain}] Starting install package autoconf"
        if check_sys packageManager yum; then
            yum install -y autoconf > /dev/null 2>&1 || echo -e "[${red}Error:${plain}] Failed to install autoconf"
        elif check_sys packageManager apt; then
            apt-get -y update > /dev/null 2>&1
            apt-get -y install autoconf > /dev/null 2>&1 || echo -e "[${red}Error:${plain}] Failed to install autoconf"
        fi
    fi
    local autoconf_ver=$(autoconf --version | grep autoconf | grep -oE "[0-9.]+")
    if version_ge ${autoconf_ver} 2.67; then
        return 0
    else
        return 1
    fi
}

get_ip(){
    local IP=$( ip addr | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | egrep -v "^192\.168|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-2]\.|^10\.|^127\.|^255\.|^0\." | head -n 1 )
    [ -z ${IP} ] && IP=$( wget -qO- -t1 -T2 ipv4.icanhazip.com )
    [ -z ${IP} ] && IP=$( wget -qO- -t1 -T2 ipinfo.io/ip )
    echo ${IP}
}

get_ipv6(){
    local ipv6=$(wget -qO- -t1 -T2 ipv6.icanhazip.com)
    [ -z ${ipv6} ] && return 1 || return 0
}

get_libev_ver(){
    libev_ver=$(wget --no-check-certificate -qO- https://api.github.com/repos/shadowsocks/shadowsocks-libev/releases/latest | grep 'tag_name' | cut -d\" -f4)
    [ -z ${libev_ver} ] && echo -e "[${red}Error${plain}] Get shadowsocks-libev latest version failed" && exit 1
}

get_opsy(){
    [ -f /etc/redhat-release ] && awk '{print ($1,$3~/^[0-9]/?$3:$4)}' /etc/redhat-release && return
    [ -f /etc/os-release ] && awk -F'[= "]' '/PRETTY_NAME/{print $3,$4,$5}' /etc/os-release && return
    [ -f /etc/lsb-release ] && awk -F'[="]+' '/DESCRIPTION/{print $2}' /etc/lsb-release && return
}

is_64bit(){
    if [ `getconf WORD_BIT` = '32' ] && [ `getconf LONG_BIT` = '64' ] ; then
        return 0
    else
        return 1
    fi
}

debianversion(){
    if check_sys sysRelease debian;then
        local version=$( get_opsy )
        local code=${1}
        local main_ver=$( echo ${version} | sed 's/[^0-9]//g')
        if [ "${main_ver}" == "${code}" ];then
            return 0
        else
            return 1
        fi
    else
        return 1
    fi
}

download(){
    local filename=$(basename $1)
    if [ -f ${1} ]; then
        echo "${filename} [found]"
    else
        echo "${filename} not found, download now..."
        wget --no-check-certificate -c -t3 -T60 -O ${1} ${2}
        if [ $? -ne 0 ]; then
            echo -e "[${red}Error${plain}] Download ${filename} failed."
            exit 1
        fi
    fi
}

download_files(){
    cd ${cur_dir}

    if   [ "${selected}" == "1" ]; then
        download "${shadowsocks_python_file}.zip" "${shadowsocks_python_url}"
        if check_sys packageManager yum; then
            download "${shadowsocks_python_init}" "${shadowsocks_python_centos}"
        elif check_sys packageManager apt; then
            download "${shadowsocks_python_init}" "${shadowsocks_python_debian}"
        fi
    elif [ "${selected}" == "2" ]; then
        download "${shadowsocks_r_file}.tar.gz" "${shadowsocks_r_url}"
        if check_sys packageManager yum; then
            download "${shadowsocks_r_init}" "${shadowsocks_r_centos}"
        elif check_sys packageManager apt; then
            download "${shadowsocks_r_init}" "${shadowsocks_r_debian}"
        fi
    elif [ "${selected}" == "3" ]; then
        if is_64bit; then
            download "${shadowsocks_go_file_64}.gz" "${shadowsocks_go_url_64}"
        else
            download "${shadowsocks_go_file_32}.gz" "${shadowsocks_go_url_32}"
        fi
        if check_sys packageManager yum; then
            download "${shadowsocks_go_init}" "${shadowsocks_go_centos}"
        elif check_sys packageManager apt; then
            download "${shadowsocks_go_init}" "${shadowsocks_go_debian}"
        fi
    elif [ "${selected}" == "4" ]; then
        get_libev_ver
        shadowsocks_libev_file="shadowsocks-libev-$(echo ${libev_ver} | sed -e 's/^[a-zA-Z]//g')"
        shadowsocks_libev_url="https://github.com/shadowsocks/shadowsocks-libev/releases/download/${libev_ver}/${shadowsocks_libev_file}.tar.gz"

        download "${shadowsocks_libev_file}.tar.gz" "${shadowsocks_libev_url}"
        if check_sys packageManager yum; then
            download "${shadowsocks_libev_init}" "${shadowsocks_libev_centos}"
        elif check_sys packageManager apt; then
            download "${shadowsocks_libev_init}" "${shadowsocks_libev_debian}"
        fi
    fi

}

get_char(){
    SAVEDSTTY=$(stty -g)
    stty -echo
    stty cbreak
    dd if=/dev/tty bs=1 count=1 2> /dev/null
    stty -raw
    stty echo
    stty $SAVEDSTTY
}

error_detect_depends(){
    local command=$1
    local depend=`echo "${command}" | awk '{print $4}'`
    echo -e "[${green}Info${plain}] Starting to install package ${depend}"
    ${command} > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo -e "[${red}Error${plain}] Failed to install ${red}${depend}${plain}"
        echo "Please visit: https://teddysun.com/486.html and contact."
        exit 1
    fi
}

config_firewall(){
    if centosversion 6; then
        /etc/init.d/iptables status > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            iptables -L -n | grep -i ${shadowsocksport} > /dev/null 2>&1
            if [ $? -ne 0 ]; then
                iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${shadowsocksport} -j ACCEPT
                iptables -I INPUT -m state --state NEW -m udp -p udp --dport ${shadowsocksport} -j ACCEPT
                /etc/init.d/iptables save
                /etc/init.d/iptables restart
            else
                echo -e "[${green}Info${plain}] port ${green}${shadowsocksport}${plain} already be enabled."
            fi
        else
            echo -e "[${yellow}Warning${plain}] iptables looks like not running or not installed, please enable port ${shadowsocksport} manually if necessary."
        fi
    elif centosversion 7; then
        systemctl status firewalld > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            default_zone=$(firewall-cmd --get-default-zone)
            firewall-cmd --permanent --zone=${default_zone} --add-port=${shadowsocksport}/tcp
            firewall-cmd --permanent --zone=${default_zone} --add-port=${shadowsocksport}/udp
            firewall-cmd --reload
        else
            echo -e "[${yellow}Warning${plain}] firewalld looks like not running or not installed, please enable port ${shadowsocksport} manually if necessary."
        fi
    fi
}

config_shadowsocks(){

if check_kernel_version && check_kernel_headers; then
    fast_open="true"
else
    fast_open="false"
fi

if   [ "${selected}" == "1" ]; then
    if [ ! -d "$(dirname ${shadowsocks_python_config})" ]; then
        mkdir -p $(dirname ${shadowsocks_python_config})
    fi
    cat > ${shadowsocks_python_config}<<-EOF
{
    "server":"0.0.0.0",
    "server_port":${shadowsocksport},
    "local_address":"127.0.0.1",
    "local_port":1080,
    "password":"${shadowsockspwd}",
    "timeout":300,
    "method":"${shadowsockscipher}",
    "fast_open":${fast_open}
}
EOF
elif [ "${selected}" == "2" ]; then
    if [ ! -d "$(dirname ${shadowsocks_r_config})" ]; then
        mkdir -p $(dirname ${shadowsocks_r_config})
    fi
    cat > ${shadowsocks_r_config}<<-EOF
{
    "server":"0.0.0.0",
    "server_ipv6":"::",
    "server_port":${shadowsocksport},
    "local_address":"127.0.0.1",
    "local_port":1080,
    "password":"${shadowsockspwd}",
    "timeout":120,
    "method":"${shadowsockscipher}",
    "protocol":"${shadowsockprotocol}",
    "protocol_param":"",
    "obfs":"${shadowsockobfs}",
    "obfs_param":"",
    "redirect":"",
    "dns_ipv6":false,
    "fast_open":${fast_open},
    "workers":1
}
EOF
elif [ "${selected}" == "3" ]; then
    if [ ! -d "$(dirname ${shadowsocks_go_config})" ]; then
        mkdir -p $(dirname ${shadowsocks_go_config})
    fi
    cat > ${shadowsocks_go_config}<<-EOF
{
    "server":"0.0.0.0",
    "server_port":${shadowsocksport},
    "local_port":1080,
    "password":"${shadowsockspwd}",
    "method":"${shadowsockscipher}",
    "timeout":300
}
EOF
elif [ "${selected}" == "4" ]; then
    local server_value="\"0.0.0.0\""
    if get_ipv6; then
        server_value="[\"[::0]\",\"0.0.0.0\"]"
    fi

    if [ ! -d "$(dirname ${shadowsocks_libev_config})" ]; then
        mkdir -p $(dirname ${shadowsocks_libev_config})
    fi

    if [ "${libev_obfs}" == "y" ] || [ "${libev_obfs}" == "Y" ]; then
        cat > ${shadowsocks_libev_config}<<-EOF
{
    "server":${server_value},
    "server_port":${shadowsocksport},
    "password":"${shadowsockspwd}",
    "timeout":300,
    "user":"nobody",
    "method":"${shadowsockscipher}",
    "fast_open":${fast_open},
    "nameserver":"8.8.8.8",
    "mode":"tcp_and_udp",
    "plugin":"obfs-server",
    "plugin_opts":"obfs=${shadowsocklibev_obfs}"
}
EOF
    else
        cat > ${shadowsocks_libev_config}<<-EOF
{
    "server":${server_value},
    "server_port":${shadowsocksport},
    "password":"${shadowsockspwd}",
    "timeout":300,
    "user":"nobody",
    "method":"${shadowsockscipher}",
    "fast_open":${fast_open},
    "nameserver":"8.8.8.8",
    "mode":"tcp_and_udp"
}
EOF
    fi

fi
}

install_dependencies(){
    if check_sys packageManager yum; then
        echo -e "[${green}Info${plain}] Checking the EPEL repository..."
        if [ ! -f /etc/yum.repos.d/epel.repo ]; then
            yum install -y epel-release > /dev/null 2>&1
        fi
        [ ! -f /etc/yum.repos.d/epel.repo ] && echo -e "[${red}Error${plain}] Install EPEL repository failed, please check it." && exit 1
        [ ! "$(command -v yum-config-manager)" ] && yum install -y yum-utils > /dev/null 2>&1
        [ x"$(yum-config-manager epel | grep -w enabled | awk '{print $3}')" != x"True" ] && yum-config-manager --enable epel > /dev/null 2>&1
        echo -e "[${green}Info${plain}] Checking the EPEL repository complete..."

        yum_depends=(
            unzip gzip openssl openssl-devel gcc python python-devel python-setuptools pcre pcre-devel libtool libevent
            autoconf automake make curl curl-devel zlib-devel perl perl-devel cpio expat-devel gettext-devel
            libev-devel c-ares-devel git qrencode
        )
        for depend in ${yum_depends[@]}; do
            error_detect_depends "yum -y install ${depend}"
        done
    elif check_sys packageManager apt; then
        apt_depends=(
            gettext build-essential unzip gzip python python-dev python-setuptools curl openssl libssl-dev
            autoconf automake libtool gcc make perl cpio libpcre3 libpcre3-dev zlib1g-dev libev-dev libc-ares-dev git qrencode
        )

        apt-get -y update
        for depend in ${apt_depends[@]}; do
            error_detect_depends "apt-get -y install ${depend}"
        done
    fi
}

install_check(){
    if check_sys packageManager yum || check_sys packageManager apt; then
        if centosversion 5; then
            return 1
        fi
        return 0
    else
        return 1
    fi
}

install_select(){
    if ! install_check; then
        echo -e "[${red}Error${plain}] Your OS is not supported to run it!"
        echo "Please change to CentOS 6+/Debian 7+/Ubuntu 12+ and try again."
        exit 1
    fi

    clear
    while true
    do
    echo  "Which Shadowsocks server you'd select:"
    for ((i=1;i<=${#software[@]};i++ )); do
        hint="${software[$i-1]}"
        echo -e "${green}${i}${plain}) ${hint}"
    done
    read -p "Please enter a number (Default ${software[0]}):" selected
    [ -z "${selected}" ] && selected="1"
    case "${selected}" in
        1|2|3|4)
        echo
        echo "You choose = ${software[${selected}-1]}"
        echo
        break
        ;;
        *)
        echo -e "[${red}Error${plain}] Please only enter a number [1-4]"
        ;;
    esac
    done
}

install_prepare_password(){
    echo "Please enter password for ${software[${selected}-1]}"
    read -p "(Default password: covernet):" shadowsockspwd
    [ -z "${shadowsockspwd}" ] && shadowsockspwd="covernet"
    echo
    echo "password = ${shadowsockspwd}"
    echo
}

install_prepare_port() {
    while true
    do
    dport=$(shuf -i 9000-19999 -n 1)
    echo -e "Please enter a port for ${software[${selected}-1]} [1-65535]"
    read -p "(Default port: ${dport}):" shadowsocksport
    [ -z "${shadowsocksport}" ] && shadowsocksport=${dport}
    expr ${shadowsocksport} + 1 &>/dev/null
    if [ $? -eq 0 ]; then
        if [ ${shadowsocksport} -ge 1 ] && [ ${shadowsocksport} -le 65535 ] && [ ${shadowsocksport:0:1} != 0 ]; then
            echo
            echo "port = ${shadowsocksport}"
            echo
            break
        fi
    fi
    echo -e "[${red}Error${plain}] Please enter a correct number [1-65535]"
    done
}

install_prepare_cipher(){
    while true
    do
    echo -e "Please select stream cipher for ${software[${selected}-1]}:"

    if   [[ "${selected}" == "1" || "${selected}" == "4" ]]; then
        for ((i=1;i<=${#common_ciphers[@]};i++ )); do
            hint="${common_ciphers[$i-1]}"
            echo -e "${green}${i}${plain}) ${hint}"
        done
        read -p "Which cipher you'd select(Default: ${common_ciphers[0]}):" pick
        [ -z "$pick" ] && pick=1
        expr ${pick} + 1 &>/dev/null
        if [ $? -ne 0 ]; then
            echo -e "[${red}Error${plain}] Please enter a number"
            continue
        fi
        if [[ "$pick" -lt 1 || "$pick" -gt ${#common_ciphers[@]} ]]; then
            echo -e "[${red}Error${plain}] Please enter a number between 1 and ${#common_ciphers[@]}"
            continue
        fi
        shadowsockscipher=${common_ciphers[$pick-1]}
    elif [ "${selected}" == "2" ]; then
        for ((i=1;i<=${#r_ciphers[@]};i++ )); do
            hint="${r_ciphers[$i-1]}"
            echo -e "${green}${i}${plain}) ${hint}"
        done
        read -p "Which cipher you'd select(Default: ${r_ciphers[1]}):" pick
        [ -z "$pick" ] && pick=2
        expr ${pick} + 1 &>/dev/null
        if [ $? -ne 0 ]; then
            echo -e "[${red}Error${plain}] Please enter a number"
            continue
        fi
        if [[ "$pick" -lt 1 || "$pick" -gt ${#r_ciphers[@]} ]]; then
            echo -e "[${red}Error${plain}] Please enter a number between 1 and ${#r_ciphers[@]}"
            continue
        fi
        shadowsockscipher=${r_ciphers[$pick-1]}
    elif [ "${selected}" == "3" ]; then
        for ((i=1;i<=${#go_ciphers[@]};i++ )); do
            hint="${go_ciphers[$i-1]}"
            echo -e "${green}${i}${plain}) ${hint}"
        done
        read -p "Which cipher you'd select(Default: ${go_ciphers[0]}):" pick
        [ -z "$pick" ] && pick=1
        expr ${pick} + 1 &>/dev/null
        if [ $? -ne 0 ]; then
            echo -e "[${red}Error${plain}] Please enter a number"
            continue
        fi
        if [[ "$pick" -lt 1 || "$pick" -gt ${#go_ciphers[@]} ]]; then
            echo -e "[${red}Error${plain}] Please enter a number between 1 and ${#go_ciphers[@]}"
            continue
        fi
        shadowsockscipher=${go_ciphers[$pick-1]}
    fi

    echo
    echo "cipher = ${shadowsockscipher}"
    echo
    break
    done
}

install_prepare_protocol(){
    while true
    do
    echo -e "Please select protocol for ${software[${selected}-1]}:"
    for ((i=1;i<=${#protocols[@]};i++ )); do
        hint="${protocols[$i-1]}"
        echo -e "${green}${i}${plain}) ${hint}"
    done
    read -p "Which protocol you'd select(Default: ${protocols[0]}):" protocol
    [ -z "$protocol" ] && protocol=1
    expr ${protocol} + 1 &>/dev/null
    if [ $? -ne 0 ]; then
        echo -e "[${red}Error${plain}] Please enter a number"
        continue
    fi
    if [[ "$protocol" -lt 1 || "$protocol" -gt ${#protocols[@]} ]]; then
        echo -e "[${red}Error${plain}] Please enter a number between 1 and ${#protocols[@]}"
        continue
    fi
    shadowsockprotocol=${protocols[$protocol-1]}
    echo
    echo "protocol = ${shadowsockprotocol}"
    echo
    break
    done
}

install_prepare_obfs(){
    while true
    do
    echo -e "Please select obfs for ${software[${selected}-1]}:"
    for ((i=1;i<=${#obfs[@]};i++ )); do
        hint="${obfs[$i-1]}"
        echo -e "${green}${i}${plain}) ${hint}"
    done
    read -p "Which obfs you'd select(Default: ${obfs[0]}):" r_obfs
    [ -z "$r_obfs" ] && r_obfs=1
    expr ${r_obfs} + 1 &>/dev/null
    if [ $? -ne 0 ]; then
        echo -e "[${red}Error${plain}] Please enter a number"
        continue
    fi
    if [[ "$r_obfs" -lt 1 || "$r_obfs" -gt ${#obfs[@]} ]]; then
        echo -e "[${red}Error${plain}] Please enter a number between 1 and ${#obfs[@]}"
        continue
    fi
    shadowsockobfs=${obfs[$r_obfs-1]}
    echo
    echo "obfs = ${shadowsockobfs}"
    echo
    break
    done
}

install_prepare_libev_obfs(){
    if autoconf_version || centosversion 6; then
        while true
        do
        echo -e "Do you want install simple-obfs for ${software[${selected}-1]}? [y/n]"
        read -p "(default: n):" libev_obfs
        [ -z "$libev_obfs" ] && libev_obfs=n
        case "${libev_obfs}" in
            y|Y|n|N)
            echo
            echo "You choose = ${libev_obfs}"
            echo
            break
            ;;
            *)
            echo -e "[${red}Error${plain}] Please only enter [y/n]"
            ;;
        esac
        done

        if [ "${libev_obfs}" == "y" ] || [ "${libev_obfs}" == "Y" ]; then
            while true
            do
            echo -e "Please select obfs for simple-obfs:"
            for ((i=1;i<=${#obfs_libev[@]};i++ )); do
                hint="${obfs_libev[$i-1]}"
                echo -e "${green}${i}${plain}) ${hint}"
            done
            read -p "Which obfs you'd select(Default: ${obfs_libev[0]}):" r_libev_obfs
            [ -z "$r_libev_obfs" ] && r_libev_obfs=1
            expr ${r_libev_obfs} + 1 &>/dev/null
            if [ $? -ne 0 ]; then
                echo -e "[${red}Error${plain}] Please enter a number"
                continue
            fi
            if [[ "$r_libev_obfs" -lt 1 || "$r_libev_obfs" -gt ${#obfs_libev[@]} ]]; then
                echo -e "[${red}Error${plain}] Please enter a number between 1 and ${#obfs_libev[@]}"
                continue
            fi
            shadowsocklibev_obfs=${obfs_libev[$r_libev_obfs-1]}
            echo
            echo "obfs = ${shadowsocklibev_obfs}"
            echo
            break
            done
        fi
    else
        echo -e "[${green}Info${plain}] autoconf version is less than 2.67, simple-obfs for ${software[${selected}-1]} installation has been skipped"
    fi
}

install_prepare(){

    if  [[ "${selected}" == "1" || "${selected}" == "3" || "${selected}" == "4" ]]; then
        install_prepare_password
        install_prepare_port
        install_prepare_cipher
        if [ "${selected}" == "4" ]; then
            install_prepare_libev_obfs
        fi
    elif [ "${selected}" == "2" ]; then
        install_prepare_password
        install_prepare_port
        install_prepare_cipher
        install_prepare_protocol
        install_prepare_obfs
    fi

    echo
    echo "Press any key to start...or Press Ctrl+C to cancel"
    char=`get_char`

}

install_libsodium(){
    if [ ! -f /usr/lib/libsodium.a ]; then
        cd ${cur_dir}
        download "${libsodium_file}.tar.gz" "${libsodium_url}"
        tar zxf ${libsodium_file}.tar.gz
        cd ${libsodium_file}
        ./configure --prefix=/usr && make && make install
        if [ $? -ne 0 ]; then
            echo -e "[${red}Error${plain}] ${libsodium_file} install failed."
            install_cleanup
            exit 1
        fi
    else
        echo -e "[${green}Info${plain}] ${libsodium_file} already installed."
    fi
}

install_mbedtls(){
    if [ ! -f /usr/lib/libmbedtls.a ]; then
        cd ${cur_dir}
        download "${mbedtls_file}-gpl.tgz" "${mbedtls_url}"
        tar xf ${mbedtls_file}-gpl.tgz
        cd ${mbedtls_file}
        make SHARED=1 CFLAGS=-fPIC
        make DESTDIR=/usr install
        if [ $? -ne 0 ]; then
            echo -e "[${red}Error${plain}] ${mbedtls_file} install failed."
            install_cleanup
            exit 1
        fi
    else
        echo -e "[${green}Info${plain}] ${mbedtls_file} already installed."
    fi
}

install_shadowsocks_python(){
    cd ${cur_dir}
    unzip -q ${shadowsocks_python_file}.zip
    if [ $? -ne 0 ];then
        echo -e "[${red}Error${plain}] unzip ${shadowsocks_python_file}.zip failed, please check unzip command."
        install_cleanup
        exit 1
    fi

    cd ${shadowsocks_python_file}
    python setup.py install --record /usr/local/shadowsocks_python.log

    if [ -f /usr/bin/ssserver ] || [ -f /usr/local/bin/ssserver ]; then
        chmod +x ${shadowsocks_python_init}
        local service_name=$(basename ${shadowsocks_python_init})
        if check_sys packageManager yum; then
            chkconfig --add ${service_name}
            chkconfig ${service_name} on
        elif check_sys packageManager apt; then
            update-rc.d -f ${service_name} defaults
        fi
    else
        echo
        echo -e "[${red}Error${plain}] ${software[0]} install failed."
        echo "Please visit: https://teddysun.com/486.html and contact."
        install_cleanup
        exit 1
    fi
}

install_shadowsocks_r(){
    cd ${cur_dir}
    tar zxf ${shadowsocks_r_file}.tar.gz
    mv ${shadowsocks_r_file}/shadowsocks /usr/local/
    if [ -f /usr/local/shadowsocks/server.py ]; then
        chmod +x ${shadowsocks_r_init}
        local service_name=$(basename ${shadowsocks_r_init})
        if check_sys packageManager yum; then
            chkconfig --add ${service_name}
            chkconfig ${service_name} on
        elif check_sys packageManager apt; then
            update-rc.d -f ${service_name} defaults
        fi
    else
        echo
        echo -e "[${red}Error${plain}] ${software[1]} install failed."
        echo "Please visit; https://teddysun.com/486.html and contact."
        install_cleanup
        exit 1
    fi
}

install_shadowsocks_go(){
    cd ${cur_dir}
    if is_64bit; then
        gzip -d ${shadowsocks_go_file_64}.gz
        if [ $? -ne 0 ];then
            echo -e "[${red}Error${plain}] Decompress ${shadowsocks_go_file_64}.gz failed."
            install_cleanup
            exit 1
        fi
        mv -f ${shadowsocks_go_file_64} /usr/bin/shadowsocks-server
    else
        gzip -d ${shadowsocks_go_file_32}.gz
        if [ $? -ne 0 ];then
            echo -e "[${red}Error${plain}] Decompress ${shadowsocks_go_file_32}.gz failed."
            install_cleanup
            exit 1
        fi
        mv -f ${shadowsocks_go_file_32} /usr/bin/shadowsocks-server
    fi

    if [ -f /usr/bin/shadowsocks-server ]; then
        chmod +x /usr/bin/shadowsocks-server
        chmod +x ${shadowsocks_go_init}

        local service_name=$(basename ${shadowsocks_go_init})
        if check_sys packageManager yum; then
            chkconfig --add ${service_name}
            chkconfig ${service_name} on
        elif check_sys packageManager apt; then
            update-rc.d -f ${service_name} defaults
        fi
    else
        echo
        echo -e "[${red}Error${plain}] ${software[2]} install failed."
        echo "Please visit: https://teddysun.com/486.html and contact."
        install_cleanup
        exit 1
    fi
}

install_shadowsocks_libev(){
    cd ${cur_dir}
    tar zxf ${shadowsocks_libev_file}.tar.gz
    cd ${shadowsocks_libev_file}
    ./configure --disable-documentation && make && make install
    if [ $? -eq 0 ]; then
        chmod +x ${shadowsocks_libev_init}
        local service_name=$(basename ${shadowsocks_libev_init})
        if check_sys packageManager yum; then
            chkconfig --add ${service_name}
            chkconfig ${service_name} on
        elif check_sys packageManager apt; then
            update-rc.d -f ${service_name} defaults
        fi
    else
        echo
        echo -e "[${red}Error${plain}] ${software[3]} install failed."
        echo "Please visit: https://teddysun.com/486.html and contact."
        install_cleanup
        exit 1
    fi
}

install_shadowsocks_libev_obfs(){
    if [ "${libev_obfs}" == "y" ] || [ "${libev_obfs}" == "Y" ]; then
        cd ${cur_dir}
        git clone https://github.com/shadowsocks/simple-obfs.git
        [ -d simple-obfs ] && cd simple-obfs || echo -e "[${red}Error:${plain}] Failed to git clone simple-obfs."
        git submodule update --init --recursive
        if centosversion 6; then
            if [ ! "$(command -v autoconf268)" ]; then
                echo -e "[${green}Info${plain}] Starting install autoconf268..."
                yum install -y autoconf268 > /dev/null 2>&1 || echo -e "[${red}Error:${plain}] Failed to install autoconf268."
            fi
            # replace command autoreconf to autoreconf268
            sed -i 's/autoreconf/autoreconf268/' autogen.sh
            # replace #include <ev.h> to #include <libev/ev.h>
            sed -i 's@^#include <ev.h>@#include <libev/ev.h>@' src/local.h
            sed -i 's@^#include <ev.h>@#include <libev/ev.h>@' src/server.h
        fi
        ./autogen.sh
        ./configure --disable-documentation
        make
        make install
        if [ ! "$(command -v obfs-server)" ]; then
            echo -e "[${red}Error${plain}] simple-obfs for ${software[${selected}-1]} install failed."
            echo "Please visit: https://teddysun.com/486.html and contact."
            install_cleanup
            exit 1
        fi
        [ -f /usr/local/bin/obfs-server ] && ln -s /usr/local/bin/obfs-server /usr/bin
    fi
}

install_completed_python(){
    clear
    ${shadowsocks_python_init} start
    echo
    echo -e "Congratulations, ${green}${software[0]}${plain} server install completed!"
    echo -e "Your Server IP        : ${red} $(get_ip) ${plain}"
    echo -e "Your Server Port      : ${red} ${shadowsocksport} ${plain}"
    echo -e "Your Password         : ${red} ${shadowsockspwd} ${plain}"
    echo -e "Your Encryption Method: ${red} ${shadowsockscipher} ${plain}"
}

install_completed_r(){
    clear
    ${shadowsocks_r_init} start
    echo
    echo -e "Congratulations, ${green}${software[1]}${plain} server install completed!"
    echo -e "Your Server IP        : ${red} $(get_ip) ${plain}"
    echo -e "Your Server Port      : ${red} ${shadowsocksport} ${plain}"
    echo -e "Your Password         : ${red} ${shadowsockspwd} ${plain}"
    echo -e "Your Protocol         : ${red} ${shadowsockprotocol} ${plain}"
    echo -e "Your obfs             : ${red} ${shadowsockobfs} ${plain}"
    echo -e "Your Encryption Method: ${red} ${shadowsockscipher} ${plain}"
}

install_completed_go(){
    clear
    ${shadowsocks_go_init} start
    echo
    echo -e "Congratulations, ${green}${software[2]}${plain} server install completed!"
    echo -e "Your Server IP        : ${red} $(get_ip) ${plain}"
    echo -e "Your Server Port      : ${red} ${shadowsocksport} ${plain}"
    echo -e "Your Password         : ${red} ${shadowsockspwd} ${plain}"
    echo -e "Your Encryption Method: ${red} ${shadowsockscipher} ${plain}"
}

install_completed_libev(){
    clear
    ldconfig
    ${shadowsocks_libev_init} start
    echo
    echo -e "Congratulations, ${green}${software[3]}${plain} server install completed!"
    echo -e "Your Server IP        : ${red} $(get_ip) ${plain}"
    echo -e "Your Server Port      : ${red} ${shadowsocksport} ${plain}"
    echo -e "Your Password         : ${red} ${shadowsockspwd} ${plain}"
    if [ "$(command -v obfs-server)" ]; then
    echo -e "Your obfs             : ${red} ${shadowsocklibev_obfs} ${plain}"
    fi
    echo -e "Your Encryption Method: ${red} ${shadowsockscipher} ${plain}"
}

qr_generate_python(){
    if [ "$(command -v qrencode)" ]; then
        local tmp=$(echo -n "${shadowsockscipher}:${shadowsockspwd}@$(get_ip):${shadowsocksport}" | base64 -w0)
        local qr_code="ss://${tmp}"
        echo
        echo "Your QR Code: (For Shadowsocks Windows, OSX, Android and iOS clients)"
        echo -e "${green} ${qr_code} ${plain}"
        echo -n "${qr_code}" | qrencode -s8 -o ${cur_dir}/shadowsocks_python_qr.png
        echo "Your QR Code has been saved as a PNG file path:"
        echo -e "${green} ${cur_dir}/shadowsocks_python_qr.png ${plain}"
	read -n 1 -r -s -p $'Press enter to continue...\n'
    fi
}

qr_generate_r(){
    if [ "$(command -v qrencode)" ]; then
        local tmp1=$(echo -n "${shadowsockspwd}" | base64 -w0 | sed 's/=//g;s/\//_/g;s/+/-/g')
        local tmp2=$(echo -n "$(get_ip):${shadowsocksport}:${shadowsockprotocol}:${shadowsockscipher}:${shadowsockobfs}:${tmp1}/?obfsparam=" | base64 -w0)
        local qr_code="ssr://${tmp2}"
        echo
        echo "Your QR Code: (For ShadowsocksR Windows, Android clients only)"
        echo -e "${green} ${qr_code} ${plain}"
        echo -n "${qr_code}" | qrencode -s8 -o ${cur_dir}/shadowsocks_r_qr.png
        echo "Your QR Code has been saved as a PNG file path:"
        echo -e "${green} ${cur_dir}/shadowsocks_r_qr.png ${plain}"
	read -n 1 -r -s -p $'Press enter to continue...\n'
    fi
}

qr_generate_go(){
    if [ "$(command -v qrencode)" ]; then
        local tmp=$(echo -n "${shadowsockscipher}:${shadowsockspwd}@$(get_ip):${shadowsocksport}" | base64 -w0)
        local qr_code="ss://${tmp}"
        echo
        echo "Your QR Code: (For Shadowsocks Windows, OSX, Android and iOS clients)"
        echo -e "${green} ${qr_code} ${plain}"
        echo -n "${qr_code}" | qrencode -s8 -o ${cur_dir}/shadowsocks_go_qr.png
        echo "Your QR Code has been saved as a PNG file path:"
        echo -e "${green} ${cur_dir}/shadowsocks_go_qr.png ${plain}"
	read -n 1 -r -s -p $'Press enter to continue...\n'
    fi
}

qr_generate_libev(){
    if [ "$(command -v qrencode)" ]; then
        local tmp=$(echo -n "${shadowsockscipher}:${shadowsockspwd}@$(get_ip):${shadowsocksport}" | base64 -w0)
        local qr_code="ss://${tmp}"
        echo
        echo "Your QR Code: (For Shadowsocks Windows, OSX, Android and iOS clients)"
        echo -e "${green} ${qr_code} ${plain}"
        echo -n "${qr_code}" | qrencode -s8 -o ${cur_dir}/shadowsocks_libev_qr.png
        echo "Your QR Code has been saved as a PNG file path:"
        echo -e "${green} ${cur_dir}/shadowsocks_libev_qr.png ${plain}"
	read -n 1 -r -s -p $'Press enter to continue...\n'
    fi
}

install_main(){
    install_libsodium
    if ! ldconfig -p | grep -wq "/usr/lib"; then
        echo "/usr/lib" > /etc/ld.so.conf.d/lib.conf
    fi
    ldconfig

    if   [ "${selected}" == "1" ]; then
        install_shadowsocks_python
        install_completed_python
        qr_generate_python
    elif [ "${selected}" == "2" ]; then
        install_shadowsocks_r
        install_completed_r
        qr_generate_r
    elif [ "${selected}" == "3" ]; then
        install_shadowsocks_go
        install_completed_go
        qr_generate_go
    elif [ "${selected}" == "4" ]; then
        install_mbedtls
        install_shadowsocks_libev
        install_shadowsocks_libev_obfs
        install_completed_libev
        qr_generate_libev
    fi

    echo
    echo "Enjoy it!"
    echo
}

install_cleanup(){
    cd ${cur_dir}
    rm -rf simple-obfs
    rm -rf ${libsodium_file} ${libsodium_file}.tar.gz
    rm -rf ${mbedtls_file} ${mbedtls_file}-gpl.tgz
    rm -rf ${shadowsocks_python_file} ${shadowsocks_python_file}.zip
    rm -rf ${shadowsocks_r_file} ${shadowsocks_r_file}.tar.gz
    rm -rf ${shadowsocks_go_file_64}.gz ${shadowsocks_go_file_32}.gz
    rm -rf ${shadowsocks_libev_file} ${shadowsocks_libev_file}.tar.gz
}

install_shadowsocks(){
    disable_selinux
    install_select
    install_prepare
    install_dependencies
    download_files
    config_shadowsocks
    if check_sys packageManager yum; then
        config_firewall
    fi
    install_main
    install_cleanup
}

uninstall_shadowsocks_python(){
    printf "Are you sure uninstall ${red}${software[0]}${plain}? [y/n]\n"
    read -p "(default: n):" answer
    [ -z ${answer} ] && answer="n"
    if [ "${answer}" == "y" ] || [ "${answer}" == "Y" ]; then
        ${shadowsocks_python_init} status > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            ${shadowsocks_python_init} stop
        fi
        local service_name=$(basename ${shadowsocks_python_init})
        if check_sys packageManager yum; then
            chkconfig --del ${service_name}
        elif check_sys packageManager apt; then
            update-rc.d -f ${service_name} remove
        fi

        rm -fr $(dirname ${shadowsocks_python_config})
        rm -f ${shadowsocks_python_init}
        rm -f /var/log/shadowsocks.log
        if [ -f /usr/local/shadowsocks_python.log ]; then
            cat /usr/local/shadowsocks_python.log | xargs rm -rf
            rm -f /usr/local/shadowsocks_python.log
        fi
        echo -e "[${green}Info${plain}] ${software[0]} uninstall success"
    else
        echo
        echo -e "[${green}Info${plain}] ${software[0]} uninstall cancelled, nothing to do..."
        echo
    fi
}

uninstall_shadowsocks_r(){
    printf "Are you sure uninstall ${red}${software[1]}${plain}? [y/n]\n"
    read -p "(default: n):" answer
    [ -z ${answer} ] && answer="n"
    if [ "${answer}" == "y" ] || [ "${answer}" == "Y" ]; then
        ${shadowsocks_r_init} status > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            ${shadowsocks_r_init} stop
        fi
        local service_name=$(basename ${shadowsocks_r_init})
        if check_sys packageManager yum; then
            chkconfig --del ${service_name}
        elif check_sys packageManager apt; then
            update-rc.d -f ${service_name} remove
        fi
        rm -fr $(dirname ${shadowsocks_r_config})
        rm -f ${shadowsocks_r_init}
        rm -f /var/log/shadowsocks.log
        rm -fr /usr/local/shadowsocks
        echo -e "[${green}Info${plain}] ${software[1]} uninstall success"
    else
        echo
        echo -e "[${green}Info${plain}] ${software[1]} uninstall cancelled, nothing to do..."
        echo
    fi
}

uninstall_shadowsocks_go(){
    printf "Are you sure uninstall ${red}${software[2]}${plain}? [y/n]\n"
    read -p "(default: n):" answer
    [ -z ${answer} ] && answer="n"
    if [ "${answer}" == "y" ] || [ "${answer}" == "Y" ]; then
        ${shadowsocks_go_init} status > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            ${shadowsocks_go_init} stop
        fi
        local service_name=$(basename ${shadowsocks_go_init})
        if check_sys packageManager yum; then
            chkconfig --del ${service_name}
        elif check_sys packageManager apt; then
            update-rc.d -f ${service_name} remove
        fi
        rm -fr $(dirname ${shadowsocks_go_config})
        rm -f ${shadowsocks_go_init}
        rm -f /usr/bin/shadowsocks-server
        echo -e "[${green}Info${plain}] ${software[2]} uninstall success"
    else
        echo
        echo -e "[${green}Info${plain}] ${software[2]} uninstall cancelled, nothing to do..."
        echo
    fi
}

uninstall_shadowsocks_libev(){
    printf "Are you sure uninstall ${red}${software[3]}${plain}? [y/n]\n"
    read -p "(default: n):" answer
    [ -z ${answer} ] && answer="n"
    if [ "${answer}" == "y" ] || [ "${answer}" == "Y" ]; then
        ${shadowsocks_libev_init} status > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            ${shadowsocks_libev_init} stop
        fi
        local service_name=$(basename ${shadowsocks_libev_init})
        if check_sys packageManager yum; then
            chkconfig --del ${service_name}
        elif check_sys packageManager apt; then
            update-rc.d -f ${service_name} remove
        fi
        rm -fr $(dirname ${shadowsocks_libev_config})
        rm -f /usr/local/bin/ss-local
        rm -f /usr/local/bin/ss-tunnel
        rm -f /usr/local/bin/ss-server
        rm -f /usr/local/bin/ss-manager
        rm -f /usr/local/bin/ss-redir
        rm -f /usr/local/bin/ss-nat
        rm -f /usr/local/bin/obfs-local
        rm -f /usr/local/bin/obfs-server
        rm -f /usr/local/lib/libshadowsocks-libev.a
        rm -f /usr/local/lib/libshadowsocks-libev.la
        rm -f /usr/local/include/shadowsocks.h
        rm -f /usr/local/lib/pkgconfig/shadowsocks-libev.pc
        rm -f /usr/local/share/man/man1/ss-local.1
        rm -f /usr/local/share/man/man1/ss-tunnel.1
        rm -f /usr/local/share/man/man1/ss-server.1
        rm -f /usr/local/share/man/man1/ss-manager.1
        rm -f /usr/local/share/man/man1/ss-redir.1
        rm -f /usr/local/share/man/man1/ss-nat.1
        rm -f /usr/local/share/man/man8/shadowsocks-libev.8
        rm -fr /usr/local/share/doc/shadowsocks-libev
        rm -f ${shadowsocks_libev_init}
        echo -e "[${green}Info${plain}] ${software[3]} uninstall success"
    else
        echo
        echo -e "[${green}Info${plain}] ${software[3]} uninstall cancelled, nothing to do..."
        echo
    fi
}

uninstall_shadowsocks(){
    while true
    do
    echo  "Which Shadowsocks server you want to uninstall?"
    for ((i=1;i<=${#software[@]};i++ )); do
        hint="${software[$i-1]}"
        echo -e "${green}${i}${plain}) ${hint}"
    done
    read -p "Please enter a number [1-4]:" un_select
    case "${un_select}" in
        1|2|3|4)
        echo
        echo "You choose = ${software[${un_select}-1]}"
        echo
        break
        ;;
        *)
        echo -e "[${red}Error${plain}] Please only enter a number [1-4]"
        ;;
    esac
    done

    if   [ "${un_select}" == "1" ]; then
        if [ -f ${shadowsocks_python_init} ]; then
            uninstall_shadowsocks_python
        else
            echo -e "[${red}Error${plain}] ${software[${un_select}-1]} not installed, please check it and try again."
            echo
            exit 1
        fi
    elif [ "${un_select}" == "2" ]; then
        if [ -f ${shadowsocks_r_init} ]; then
            uninstall_shadowsocks_r
        else
            echo -e "[${red}Error${plain}] ${software[${un_select}-1]} not installed, please check it and try again."
            echo
            exit 1
        fi
    elif [ "${un_select}" == "3" ]; then
        if [ -f ${shadowsocks_go_init} ]; then
            uninstall_shadowsocks_go
        else
            echo -e "[${red}Error${plain}] ${software[${un_select}-1]} not installed, please check it and try again."
            echo
            exit 1
        fi
    elif [ "${un_select}" == "4" ]; then
        if [ -f ${shadowsocks_libev_init} ]; then
            uninstall_shadowsocks_libev
        else
            echo -e "[${red}Error${plain}] ${software[${un_select}-1]} not installed, please check it and try again."
            echo
            exit 1
        fi
    fi
}

# Initialization step
action=$1
[ -z $1 ] && action=install
case "${action}" in
    install|uninstall)
        ${action}_shadowsocks
        ;;
    *)
        echo "Arguments error! [${action}]"
        echo "Usage: $(basename $0) [install|uninstall]"
        ;;
esac
}
function installwiregaurd(){
preinst
# Detect Debian users running the script with "sh" instead of bash
if readlink /proc/$$/exe | grep -q "dash"; then
	echo 'This installer needs to be run with "bash", not "sh".'
	exit
fi

# Discard stdin. Needed when running from an one-liner which includes a newline
read -N 999999 -t 0.001

# Detect OpenVZ 6
if [[ $(uname -r | cut -d "." -f 1) -eq 2 ]]; then
	echo "The system is running an old kernel, which is incompatible with this installer."
	exit
fi

# Detect OS
# $os_version variables aren't always in use, but are kept here for convenience
if grep -qs "ubuntu" /etc/os-release; then
	os="ubuntu"
	os_version=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.')
elif [[ -e /etc/debian_version ]]; then
	os="debian"
	os_version=$(grep -oE '[0-9]+' /etc/debian_version | head -1)
elif [[ -e /etc/almalinux-release || -e /etc/rocky-release || -e /etc/centos-release ]]; then
	os="centos"
	os_version=$(grep -shoE '[0-9]+' /etc/almalinux-release /etc/rocky-release /etc/centos-release | head -1)
elif [[ -e /etc/fedora-release ]]; then
	os="fedora"
	os_version=$(grep -oE '[0-9]+' /etc/fedora-release | head -1)
else
	echo "This installer seems to be running on an unsupported distribution.
Supported distros are Ubuntu, Debian, AlmaLinux, Rocky Linux, CentOS and Fedora."
	exit
fi

if [[ "$os" == "ubuntu" && "$os_version" -lt 1804 ]]; then
	echo "Ubuntu 18.04 or higher is required to use this installer.
This version of Ubuntu is too old and unsupported."
	exit
fi

if [[ "$os" == "debian" && "$os_version" -lt 10 ]]; then
	echo "Debian 10 or higher is required to use this installer.
This version of Debian is too old and unsupported."
	exit
fi

if [[ "$os" == "centos" && "$os_version" -lt 7 ]]; then
	echo "CentOS 7 or higher is required to use this installer.
This version of CentOS is too old and unsupported."
	exit
fi

# Detect environments where $PATH does not include the sbin directories
if ! grep -q sbin <<< "$PATH"; then
	echo '$PATH does not include sbin. Try using "su -" instead of "su".'
	exit
fi

systemd-detect-virt -cq
is_container="$?"

if [[ "$os" == "fedora" && "$os_version" -eq 31 && $(uname -r | cut -d "." -f 2) -lt 6 && ! "$is_container" -eq 0 ]]; then
	echo 'Fedora 31 is supported, but the kernel is outdated.
Upgrade the kernel using "dnf upgrade kernel" and restart.'
	exit
fi

if [[ "$EUID" -ne 0 ]]; then
	echo "This installer needs to be run with superuser privileges."
	exit
fi

if [[ "$is_container" -eq 0 ]]; then
	if [ "$(uname -m)" != "x86_64" ]; then
		echo "In containerized systems, this installer supports only the x86_64 architecture.
The system runs on $(uname -m) and is unsupported."
		exit
	fi
	# TUN device is required to use BoringTun if running inside a container
	if [[ ! -e /dev/net/tun ]] || ! ( exec 7<>/dev/net/tun ) 2>/dev/null; then
		echo "The system does not have the TUN device available.
TUN needs to be enabled before running this installer."
		exit
	fi
fi

new_client_dns () {
	echo "Select a DNS server for the client:"
	echo "   1) Current system resolvers"
	echo "   2) Google"
	echo "   3) 1.1.1.1"
	echo "   4) OpenDNS"
	echo "   5) Quad9"
	echo "   6) AdGuard"
	read -p "DNS server [1]: " dns
	until [[ -z "$dns" || "$dns" =~ ^[1-6]$ ]]; do
		echo "$dns: invalid selection."
		read -p "DNS server [1]: " dns
	done
		# DNS
	case "$dns" in
		1|"")
			# Locate the proper resolv.conf
			# Needed for systems running systemd-resolved
			if grep -q '^nameserver 127.0.0.53' "/etc/resolv.conf"; then
				resolv_conf="/run/systemd/resolve/resolv.conf"
			else
				resolv_conf="/etc/resolv.conf"
			fi
			# Extract nameservers and provide them in the required format
			dns=$(grep -v '^#\|^;' "$resolv_conf" | grep '^nameserver' | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | xargs | sed -e 's/ /, /g')
		;;
		2)
			dns="8.8.8.8, 8.8.4.4"
		;;
		3)
			dns="1.1.1.1, 1.0.0.1"
		;;
		4)
			dns="208.67.222.222, 208.67.220.220"
		;;
		5)
			dns="9.9.9.9, 149.112.112.112"
		;;
		6)
			dns="94.140.14.14, 94.140.15.15"
		;;
	esac
}

new_client_setup () {
	# Given a list of the assigned internal IPv4 addresses, obtain the lowest still
	# available octet. Important to start looking at 2, because 1 is our gateway.
	octet=2
	while grep AllowedIPs /etc/wireguard/wg0.conf | cut -d "." -f 4 | cut -d "/" -f 1 | grep -q "$octet"; do
		(( octet++ ))
	done
	# Don't break the WireGuard configuration in case the address space is full
	if [[ "$octet" -eq 255 ]]; then
		echo "253 clients are already configured. The WireGuard internal subnet is full!"
		exit
	fi
	key=$(wg genkey)
	psk=$(wg genpsk)
	# Configure client in the server
	cat << EOF >> /etc/wireguard/wg0.conf
# BEGIN_PEER $client
[Peer]
PublicKey = $(wg pubkey <<< $key)
PresharedKey = $psk
AllowedIPs = 10.7.0.$octet/32$(grep -q 'fddd:2c4:2c4:2c4::1' /etc/wireguard/wg0.conf && echo ", fddd:2c4:2c4:2c4::$octet/128")
# END_PEER $client
EOF
	# Create client configuration
	cat << EOF > ~/"$client".conf
[Interface]
Address = 10.7.0.$octet/24$(grep -q 'fddd:2c4:2c4:2c4::1' /etc/wireguard/wg0.conf && echo ", fddd:2c4:2c4:2c4::$octet/64")
DNS = $dns
PrivateKey = $key
[Peer]
PublicKey = $(grep PrivateKey /etc/wireguard/wg0.conf | cut -d " " -f 3 | wg pubkey)
PresharedKey = $psk
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = $(grep '^# ENDPOINT' /etc/wireguard/wg0.conf | cut -d " " -f 3):$(grep ListenPort /etc/wireguard/wg0.conf | cut -d " " -f 3)
PersistentKeepalive = 25
EOF
}

if [[ ! -e /etc/wireguard/wg0.conf ]]; then
	# Detect some Debian minimal setups where neither wget nor curl are installed
	if ! hash wget 2>/dev/null && ! hash curl 2>/dev/null; then
		echo "Wget is required to use this installer."
		read -n1 -r -p "Press any key to install Wget and continue..."
		apt-get update
		apt-get install -y wget
	fi
	clear
	echo 'Welcome to this WireGuard installer!'
	# If system has a single IPv4, it is selected automatically. Else, ask the user
	if [[ $(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}') -eq 1 ]]; then
		ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}')
	else
		number_of_ip=$(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}')
		echo
		echo "Which IPv4 address should be used?"
		ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | nl -s ') '
		read -p "IPv4 address [1]: " ip_number
		until [[ -z "$ip_number" || "$ip_number" =~ ^[0-9]+$ && "$ip_number" -le "$number_of_ip" ]]; do
			echo "$ip_number: invalid selection."
			read -p "IPv4 address [1]: " ip_number
		done
		[[ -z "$ip_number" ]] && ip_number="1"
		ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | sed -n "$ip_number"p)
	fi
	# If $ip is a private IP address, the server must be behind NAT
	if echo "$ip" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
		echo
		echo "This server is behind NAT. What is the public IPv4 address or hostname?"
		# Get public IP and sanitize with grep
		get_public_ip=$(grep -m 1 -oE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' <<< "$(wget -T 10 -t 1 -4qO- "http://ip1.dynupdate.no-ip.com/" || curl -m 10 -4Ls "http://ip1.dynupdate.no-ip.com/")")
		read -p "Public IPv4 address / hostname [$get_public_ip]: " public_ip
		# If the checkip service is unavailable and user didn't provide input, ask again
		until [[ -n "$get_public_ip" || -n "$public_ip" ]]; do
			echo "Invalid input."
			read -p "Public IPv4 address / hostname: " public_ip
		done
		[[ -z "$public_ip" ]] && public_ip="$get_public_ip"
	fi
	# If system has a single IPv6, it is selected automatically
	if [[ $(ip -6 addr | grep -c 'inet6 [23]') -eq 1 ]]; then
		ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}')
	fi
	# If system has multiple IPv6, ask the user to select one
	if [[ $(ip -6 addr | grep -c 'inet6 [23]') -gt 1 ]]; then
		number_of_ip6=$(ip -6 addr | grep -c 'inet6 [23]')
		echo
		echo "Which IPv6 address should be used?"
		ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | nl -s ') '
		read -p "IPv6 address [1]: " ip6_number
		until [[ -z "$ip6_number" || "$ip6_number" =~ ^[0-9]+$ && "$ip6_number" -le "$number_of_ip6" ]]; do
			echo "$ip6_number: invalid selection."
			read -p "IPv6 address [1]: " ip6_number
		done
		[[ -z "$ip6_number" ]] && ip6_number="1"
		ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | sed -n "$ip6_number"p)
	fi
	echo
	echo "What port should WireGuard listen to?"
	read -p "Port [51820]: " port
	until [[ -z "$port" || "$port" =~ ^[0-9]+$ && "$port" -le 65535 ]]; do
		echo "$port: invalid port."
		read -p "Port [51820]: " port
	done
	[[ -z "$port" ]] && port="51820"
	echo
	echo "Enter a name for the first client:"
	read -p "Name [client]: " unsanitized_client
	# Allow a limited set of characters to avoid conflicts
	client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
	[[ -z "$client" ]] && client="client"
	echo
	new_client_dns
	# Set up automatic updates for BoringTun if the user is fine with that
	if [[ "$is_container" -eq 0 ]]; then
		echo
		echo "BoringTun will be installed to set up WireGuard in the system."
		read -p "Should automatic updates be enabled for it? [Y/n]: " boringtun_updates
		until [[ "$boringtun_updates" =~ ^[yYnN]*$ ]]; do
			echo "$remove: invalid selection."
			read -p "Should automatic updates be enabled for it? [Y/n]: " boringtun_updates
		done
		[[ -z "$boringtun_updates" ]] && boringtun_updates="y"
		if [[ "$boringtun_updates" =~ ^[yY]$ ]]; then
			if [[ "$os" == "centos" || "$os" == "fedora" ]]; then
				cron="cronie"
			elif [[ "$os" == "debian" || "$os" == "ubuntu" ]]; then
				cron="cron"
			fi
		fi
	fi
	echo
	echo "WireGuard installation is ready to begin."
	# Install a firewall if firewalld or iptables are not already available
	if ! systemctl is-active --quiet firewalld.service && ! hash iptables 2>/dev/null; then
		if [[ "$os" == "centos" || "$os" == "fedora" ]]; then
			firewall="firewalld"
			# We don't want to silently enable firewalld, so we give a subtle warning
			# If the user continues, firewalld will be installed and enabled during setup
			echo "firewalld, which is required to manage routing tables, will also be installed."
		elif [[ "$os" == "debian" || "$os" == "ubuntu" ]]; then
			# iptables is way less invasive than firewalld so no warning is given
			firewall="iptables"
		fi
	fi
	read -n1 -r -p "Press any key to continue..."
	# Install WireGuard
	# If not running inside a container, set up the WireGuard kernel module
	if [[ ! "$is_container" -eq 0 ]]; then
		if [[ "$os" == "ubuntu" ]]; then
			# Ubuntu
			apt-get update
			apt-get install -y wireguard qrencode $firewall
		elif [[ "$os" == "debian" && "$os_version" -ge 11 ]]; then
			# Debian 11 or higher
			apt-get update
			apt-get install -y wireguard qrencode $firewall
		elif [[ "$os" == "debian" && "$os_version" -eq 10 ]]; then
			# Debian 10
			if ! grep -qs '^deb .* buster-backports main' /etc/apt/sources.list /etc/apt/sources.list.d/*.list; then
				echo "deb http://deb.debian.org/debian buster-backports main" >> /etc/apt/sources.list
			fi
			apt-get update
			# Try to install kernel headers for the running kernel and avoid a reboot. This
			# can fail, so it's important to run separately from the other apt-get command.
			apt-get install -y linux-headers-"$(uname -r)"
			# There are cleaner ways to find out the $architecture, but we require an
			# specific format for the package name and this approach provides what we need.
			architecture=$(dpkg --get-selections 'linux-image-*-*' | cut -f 1 | grep -oE '[^-]*$' -m 1)
			# linux-headers-$architecture points to the latest headers. We install it
			# because if the system has an outdated kernel, there is no guarantee that old
			# headers were still downloadable and to provide suitable headers for future
			# kernel updates.
			apt-get install -y linux-headers-"$architecture"
			apt-get install -y wireguard qrencode $firewall
		elif [[ "$os" == "centos" && "$os_version" -eq 8 ]]; then
			# CentOS 8
			dnf install -y epel-release elrepo-release
			dnf install -y kmod-wireguard wireguard-tools qrencode $firewall
			mkdir -p /etc/wireguard/
		elif [[ "$os" == "centos" && "$os_version" -eq 7 ]]; then
			# CentOS 7
			yum install -y epel-release https://www.elrepo.org/elrepo-release-7.el7.elrepo.noarch.rpm
			yum install -y yum-plugin-elrepo
			yum install -y kmod-wireguard wireguard-tools qrencode $firewall
			mkdir -p /etc/wireguard/
		elif [[ "$os" == "fedora" ]]; then
			# Fedora
			dnf install -y wireguard-tools qrencode $firewall
			mkdir -p /etc/wireguard/
		fi
	# Else, we are inside a container and BoringTun needs to be used
	else
		# Install required packages
		if [[ "$os" == "ubuntu" ]]; then
			# Ubuntu
			apt-get update
			apt-get install -y qrencode ca-certificates $cron $firewall
			apt-get install -y wireguard-tools --no-install-recommends
		elif [[ "$os" == "debian" && "$os_version" -ge 11 ]]; then
			# Debian 11 or higher
			apt-get update
			apt-get install -y qrencode ca-certificates $cron $firewall
			apt-get install -y wireguard-tools --no-install-recommends
		elif [[ "$os" == "debian" && "$os_version" -eq 10 ]]; then
			# Debian 10
			if ! grep -qs '^deb .* buster-backports main' /etc/apt/sources.list /etc/apt/sources.list.d/*.list; then
				echo "deb http://deb.debian.org/debian buster-backports main" >> /etc/apt/sources.list
			fi
			apt-get update
			apt-get install -y qrencode ca-certificates $cron $firewall
			apt-get install -y wireguard-tools --no-install-recommends
		elif [[ "$os" == "centos" && "$os_version" -eq 8 ]]; then
			# CentOS 8
			dnf install -y epel-release
			dnf install -y wireguard-tools qrencode ca-certificates tar $cron $firewall
			mkdir -p /etc/wireguard/
		elif [[ "$os" == "centos" && "$os_version" -eq 7 ]]; then
			# CentOS 7
			yum install -y epel-release
			yum install -y wireguard-tools qrencode ca-certificates tar $cron $firewall
			mkdir -p /etc/wireguard/
		elif [[ "$os" == "fedora" ]]; then
			# Fedora
			dnf install -y wireguard-tools qrencode ca-certificates tar $cron $firewall
			mkdir -p /etc/wireguard/
		fi
		# Grab the BoringTun binary using wget or curl and extract into the right place.
		# Don't use this service elsewhere without permission! Contact me before you do!
		{ wget -qO- https://wg.nyr.be/1/latest/download 2>/dev/null || curl -sL https://wg.nyr.be/1/latest/download ; } | tar xz -C /usr/local/sbin/ --wildcards 'boringtun-*/boringtun' --strip-components 1
		# Configure wg-quick to use BoringTun
		mkdir /etc/systemd/system/wg-quick@wg0.service.d/ 2>/dev/null
		echo "[Service]
Environment=WG_QUICK_USERSPACE_IMPLEMENTATION=boringtun
Environment=WG_SUDO=1" > /etc/systemd/system/wg-quick@wg0.service.d/boringtun.conf
		if [[ -n "$cron" ]] && [[ "$os" == "centos" || "$os" == "fedora" ]]; then
			systemctl enable --now crond.service
		fi
	fi
	# If firewalld was just installed, enable it
	if [[ "$firewall" == "firewalld" ]]; then
		systemctl enable --now firewalld.service
	fi
	# Generate wg0.conf
	cat << EOF > /etc/wireguard/wg0.conf
# Do not alter the commented lines
# They are used by wireguard-install
# ENDPOINT $([[ -n "$public_ip" ]] && echo "$public_ip" || echo "$ip")
[Interface]
Address = 10.7.0.1/24$([[ -n "$ip6" ]] && echo ", fddd:2c4:2c4:2c4::1/64")
PrivateKey = $(wg genkey)
ListenPort = $port
EOF
	chmod 600 /etc/wireguard/wg0.conf
	# Enable net.ipv4.ip_forward for the system
	echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-wireguard-forward.conf
	# Enable without waiting for a reboot or service restart
	echo 1 > /proc/sys/net/ipv4/ip_forward
	if [[ -n "$ip6" ]]; then
		# Enable net.ipv6.conf.all.forwarding for the system
		echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.d/99-wireguard-forward.conf
		# Enable without waiting for a reboot or service restart
		echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
	fi
	if systemctl is-active --quiet firewalld.service; then
		# Using both permanent and not permanent rules to avoid a firewalld
		# reload.
		firewall-cmd --add-port="$port"/udp
		firewall-cmd --zone=trusted --add-source=10.7.0.0/24
		firewall-cmd --permanent --add-port="$port"/udp
		firewall-cmd --permanent --zone=trusted --add-source=10.7.0.0/24
		# Set NAT for the VPN subnet
		firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j SNAT --to "$ip"
		firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j SNAT --to "$ip"
		if [[ -n "$ip6" ]]; then
			firewall-cmd --zone=trusted --add-source=fddd:2c4:2c4:2c4::/64
			firewall-cmd --permanent --zone=trusted --add-source=fddd:2c4:2c4:2c4::/64
			firewall-cmd --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:2c4:2c4:2c4::/64 ! -d fddd:2c4:2c4:2c4::/64 -j SNAT --to "$ip6"
			firewall-cmd --permanent --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:2c4:2c4:2c4::/64 ! -d fddd:2c4:2c4:2c4::/64 -j SNAT --to "$ip6"
		fi
	else
		# Create a service to set up persistent iptables rules
		iptables_path=$(command -v iptables)
		ip6tables_path=$(command -v ip6tables)
		# nf_tables is not available as standard in OVZ kernels. So use iptables-legacy
		# if we are in OVZ, with a nf_tables backend and iptables-legacy is available.
		if [[ $(systemd-detect-virt) == "openvz" ]] && readlink -f "$(command -v iptables)" | grep -q "nft" && hash iptables-legacy 2>/dev/null; then
			iptables_path=$(command -v iptables-legacy)
			ip6tables_path=$(command -v ip6tables-legacy)
		fi
		echo "[Unit]
Before=network.target
[Service]
Type=oneshot
ExecStart=$iptables_path -t nat -A POSTROUTING -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j SNAT --to $ip
ExecStart=$iptables_path -I INPUT -p udp --dport $port -j ACCEPT
ExecStart=$iptables_path -I FORWARD -s 10.7.0.0/24 -j ACCEPT
ExecStart=$iptables_path -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$iptables_path -t nat -D POSTROUTING -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j SNAT --to $ip
ExecStop=$iptables_path -D INPUT -p udp --dport $port -j ACCEPT
ExecStop=$iptables_path -D FORWARD -s 10.7.0.0/24 -j ACCEPT
ExecStop=$iptables_path -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" > /etc/systemd/system/wg-iptables.service
		if [[ -n "$ip6" ]]; then
			echo "ExecStart=$ip6tables_path -t nat -A POSTROUTING -s fddd:2c4:2c4:2c4::/64 ! -d fddd:2c4:2c4:2c4::/64 -j SNAT --to $ip6
ExecStart=$ip6tables_path -I FORWARD -s fddd:2c4:2c4:2c4::/64 -j ACCEPT
ExecStart=$ip6tables_path -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$ip6tables_path -t nat -D POSTROUTING -s fddd:2c4:2c4:2c4::/64 ! -d fddd:2c4:2c4:2c4::/64 -j SNAT --to $ip6
ExecStop=$ip6tables_path -D FORWARD -s fddd:2c4:2c4:2c4::/64 -j ACCEPT
ExecStop=$ip6tables_path -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" >> /etc/systemd/system/wg-iptables.service
		fi
		echo "RemainAfterExit=yes
[Install]
WantedBy=multi-user.target" >> /etc/systemd/system/wg-iptables.service
		systemctl enable --now wg-iptables.service
	fi
	# Generates the custom client.conf
	new_client_setup
	# Enable and start the wg-quick service
	systemctl enable --now wg-quick@wg0.service
	# Set up automatic updates for BoringTun if the user wanted to
	if [[ "$boringtun_updates" =~ ^[yY]$ ]]; then
		# Deploy upgrade script
		cat << 'EOF' > /usr/local/sbin/boringtun-upgrade
#!/bin/bash
latest=$(wget -qO- https://wg.nyr.be/1/latest 2>/dev/null || curl -sL https://wg.nyr.be/1/latest 2>/dev/null)
# If server did not provide an appropriate response, exit
if ! head -1 <<< "$latest" | grep -qiE "^boringtun.+[0-9]+\.[0-9]+.*$"; then
	echo "Update server unavailable"
	exit
fi
current=$(/usr/local/sbin/boringtun -V)
if [[ "$current" != "$latest" ]]; then
	download="https://wg.nyr.be/1/latest/download"
	xdir=$(mktemp -d)
	# If download and extraction are successful, upgrade the boringtun binary
	if { wget -qO- "$download" 2>/dev/null || curl -sL "$download" ; } | tar xz -C "$xdir" --wildcards "boringtun-*/boringtun" --strip-components 1; then
		systemctl stop wg-quick@wg0.service
		rm -f /usr/local/sbin/boringtun
		mv "$xdir"/boringtun /usr/local/sbin/boringtun
		systemctl start wg-quick@wg0.service
		echo "Succesfully updated to $(/usr/local/sbin/boringtun -V)"
	else
		echo "boringtun update failed"
	fi
	rm -rf "$xdir"
else
	echo "$current is up to date"
fi
EOF
		chmod +x /usr/local/sbin/boringtun-upgrade
		# Add cron job to run the updater daily at a random time between 3:00 and 5:59
		{ crontab -l 2>/dev/null; echo "$(( $RANDOM % 60 )) $(( $RANDOM % 3 + 3 )) * * * /usr/local/sbin/boringtun-upgrade &>/dev/null" ; } | crontab -
	fi
	echo
	qrencode -t UTF8 < ~/"$client.conf"
	echo -e '\xE2\x86\x91 That is a QR code containing the client configuration.'
	echo
	# If the kernel module didn't load, system probably had an outdated kernel
	# We'll try to help, but will not will not force a kernel upgrade upon the user
	if [[ ! "$is_container" -eq 0 ]] && ! modprobe -nq wireguard; then
		echo "Warning!"
		echo "Installation was finished, but the WireGuard kernel module could not load."
		if [[ "$os" == "ubuntu" && "$os_version" -eq 1804 ]]; then
		echo 'Upgrade the kernel and headers with "apt-get install linux-generic" and restart.'
		elif [[ "$os" == "debian" && "$os_version" -eq 10 ]]; then
		echo "Upgrade the kernel with \"apt-get install linux-image-$architecture\" and restart."
		elif [[ "$os" == "centos" && "$os_version" -le 8 ]]; then
			echo "Reboot the system to load the most recent kernel."
		fi
	else
		echo "Finished!"
	fi
	echo
	echo "The client configuration is available in:" ~/"$client.conf"
	echo "New clients can be added by running this script again."
else
	clear
	echo "WireGuard is already installed."
	echo
	echo "Select an option:"
	echo "   1) Add a new client"
	echo "   2) Remove an existing client"
	echo "   3) Remove WireGuard"
	echo "   4) Exit"
	read -p "Option: " option
	until [[ "$option" =~ ^[1-4]$ ]]; do
		echo "$option: invalid selection."
		read -p "Option: " option
	done
	case "$option" in
		1)
			echo
			echo "Provide a name for the client:"
			read -p "Name: " unsanitized_client
			# Allow a limited set of characters to avoid conflicts
			client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
			while [[ -z "$client" ]] || grep -q "^# BEGIN_PEER $client$" /etc/wireguard/wg0.conf; do
				echo "$client: invalid name."
				read -p "Name: " unsanitized_client
				client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
			done
			echo
			new_client_dns
			new_client_setup
			# Append new client configuration to the WireGuard interface
			wg addconf wg0 <(sed -n "/^# BEGIN_PEER $client/,/^# END_PEER $client/p" /etc/wireguard/wg0.conf)
			echo
			qrencode -t UTF8 < ~/"$client.conf"
			echo -e '\xE2\x86\x91 That is a QR code containing your client configuration.'
			echo
			echo "$client added. Configuration available in:" ~/"$client.conf"
			exit
		;;
		2)
			# This option could be documented a bit better and maybe even be simplified
			# ...but what can I say, I want some sleep too
			number_of_clients=$(grep -c '^# BEGIN_PEER' /etc/wireguard/wg0.conf)
			if [[ "$number_of_clients" = 0 ]]; then
				echo
				echo "There are no existing clients!"
				exit
			fi
			echo
			echo "Select the client to remove:"
			grep '^# BEGIN_PEER' /etc/wireguard/wg0.conf | cut -d ' ' -f 3 | nl -s ') '
			read -p "Client: " client_number
			until [[ "$client_number" =~ ^[0-9]+$ && "$client_number" -le "$number_of_clients" ]]; do
				echo "$client_number: invalid selection."
				read -p "Client: " client_number
			done
			client=$(grep '^# BEGIN_PEER' /etc/wireguard/wg0.conf | cut -d ' ' -f 3 | sed -n "$client_number"p)
			echo
			read -p "Confirm $client removal? [y/N]: " remove
			until [[ "$remove" =~ ^[yYnN]*$ ]]; do
				echo "$remove: invalid selection."
				read -p "Confirm $client removal? [y/N]: " remove
			done
			if [[ "$remove" =~ ^[yY]$ ]]; then
				# The following is the right way to avoid disrupting other active connections:
				# Remove from the live interface
				wg set wg0 peer "$(sed -n "/^# BEGIN_PEER $client$/,\$p" /etc/wireguard/wg0.conf | grep -m 1 PublicKey | cut -d " " -f 3)" remove
				# Remove from the configuration file
				sed -i "/^# BEGIN_PEER $client$/,/^# END_PEER $client$/d" /etc/wireguard/wg0.conf
				echo
				echo "$client removed!"
			else
				echo
				echo "$client removal aborted!"
			fi
			exit
		;;
		3)
			echo
			read -p "Confirm WireGuard removal? [y/N]: " remove
			until [[ "$remove" =~ ^[yYnN]*$ ]]; do
				echo "$remove: invalid selection."
				read -p "Confirm WireGuard removal? [y/N]: " remove
			done
			if [[ "$remove" =~ ^[yY]$ ]]; then
				port=$(grep '^ListenPort' /etc/wireguard/wg0.conf | cut -d " " -f 3)
				if systemctl is-active --quiet firewalld.service; then
					ip=$(firewall-cmd --direct --get-rules ipv4 nat POSTROUTING | grep '\-s 10.7.0.0/24 '"'"'!'"'"' -d 10.7.0.0/24' | grep -oE '[^ ]+$')
					# Using both permanent and not permanent rules to avoid a firewalld reload.
					firewall-cmd --remove-port="$port"/udp
					firewall-cmd --zone=trusted --remove-source=10.7.0.0/24
					firewall-cmd --permanent --remove-port="$port"/udp
					firewall-cmd --permanent --zone=trusted --remove-source=10.7.0.0/24
					firewall-cmd --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j SNAT --to "$ip"
					firewall-cmd --permanent --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j SNAT --to "$ip"
					if grep -qs 'fddd:2c4:2c4:2c4::1/64' /etc/wireguard/wg0.conf; then
						ip6=$(firewall-cmd --direct --get-rules ipv6 nat POSTROUTING | grep '\-s fddd:2c4:2c4:2c4::/64 '"'"'!'"'"' -d fddd:2c4:2c4:2c4::/64' | grep -oE '[^ ]+$')
						firewall-cmd --zone=trusted --remove-source=fddd:2c4:2c4:2c4::/64
						firewall-cmd --permanent --zone=trusted --remove-source=fddd:2c4:2c4:2c4::/64
						firewall-cmd --direct --remove-rule ipv6 nat POSTROUTING 0 -s fddd:2c4:2c4:2c4::/64 ! -d fddd:2c4:2c4:2c4::/64 -j SNAT --to "$ip6"
						firewall-cmd --permanent --direct --remove-rule ipv6 nat POSTROUTING 0 -s fddd:2c4:2c4:2c4::/64 ! -d fddd:2c4:2c4:2c4::/64 -j SNAT --to "$ip6"
					fi
				else
					systemctl disable --now wg-iptables.service
					rm -f /etc/systemd/system/wg-iptables.service
				fi
				systemctl disable --now wg-quick@wg0.service
				rm -f /etc/systemd/system/wg-quick@wg0.service.d/boringtun.conf
				rm -f /etc/sysctl.d/99-wireguard-forward.conf
				# Different packages were installed if the system was containerized or not
				if [[ ! "$is_container" -eq 0 ]]; then
					if [[ "$os" == "ubuntu" ]]; then
						# Ubuntu
						rm -rf /etc/wireguard/
						apt-get remove --purge -y wireguard wireguard-tools
					elif [[ "$os" == "debian" && "$os_version" -ge 11 ]]; then
						# Debian 11 or higher
						rm -rf /etc/wireguard/
						apt-get remove --purge -y wireguard wireguard-tools
					elif [[ "$os" == "debian" && "$os_version" -eq 10 ]]; then
						# Debian 10
						rm -rf /etc/wireguard/
						apt-get remove --purge -y wireguard wireguard-dkms wireguard-tools
					elif [[ "$os" == "centos" && "$os_version" -eq 8 ]]; then
						# CentOS 8
						dnf remove -y kmod-wireguard wireguard-tools
						rm -rf /etc/wireguard/
					elif [[ "$os" == "centos" && "$os_version" -eq 7 ]]; then
						# CentOS 7
						yum remove -y kmod-wireguard wireguard-tools
						rm -rf /etc/wireguard/
					elif [[ "$os" == "fedora" ]]; then
						# Fedora
						dnf remove -y wireguard-tools
						rm -rf /etc/wireguard/
					fi
				else
					{ crontab -l 2>/dev/null | grep -v '/usr/local/sbin/boringtun-upgrade' ; } | crontab -
					if [[ "$os" == "ubuntu" ]]; then
						# Ubuntu
						rm -rf /etc/wireguard/
						apt-get remove --purge -y wireguard-tools
					elif [[ "$os" == "debian" && "$os_version" -ge 11 ]]; then
						# Debian 11 or higher
						rm -rf /etc/wireguard/
						apt-get remove --purge -y wireguard-tools
					elif [[ "$os" == "debian" && "$os_version" -eq 10 ]]; then
						# Debian 10
						rm -rf /etc/wireguard/
						apt-get remove --purge -y wireguard-tools
					elif [[ "$os" == "centos" && "$os_version" -eq 8 ]]; then
						# CentOS 8
						dnf remove -y wireguard-tools
						rm -rf /etc/wireguard/
					elif [[ "$os" == "centos" && "$os_version" -eq 7 ]]; then
						# CentOS 7
						yum remove -y wireguard-tools
						rm -rf /etc/wireguard/
					elif [[ "$os" == "fedora" ]]; then
						# Fedora
						dnf remove -y wireguard-tools
						rm -rf /etc/wireguard/
					fi
					rm -f /usr/local/sbin/boringtun /usr/local/sbin/boringtun-upgrade
				fi
				echo
				echo "WireGuard removed!"
			else
				echo
				echo "WireGuard removal aborted!"
			fi
			exit
		;;
		4)
			exit
		;;
	esac
fi
}
function installopenvpnas(){
preinst
clear
wget --no-check-certificate --user=covernet --password=u1rGiEkhAN https://akhvash.ir/as/openvpn-as-bundled-clients_25_all.deb -O /tmp/openvpn-as-bundled-clients_25_all.deb
wget --no-check-certificate --user=covernet --password=u1rGiEkhAN https://akhvash.ir/as/openvpn-as_2.11.0-794ab41d-Ubuntu20_amd64.deb -O /tmp/openvpn-as_2.11.0-794ab41d-Ubuntu20_amd64.deb
wget --no-check-certificate --user=covernet --password=u1rGiEkhAN https://akhvash.ir/as/pyovpn-2.0-py3.8.egg -O /tmp/pyovpn-2.0-py3.8.egg
apt-get install mysql-client libmysqlclient-dev -y
apt install /tmp/openvpn-as-bundled-clients_25_all.deb -y
apt install /tmp/openvpn-as_2.11.0-794ab41d-Ubuntu20_amd64.deb -y
mv /tmp/pyovpn-2.0-py3.8.egg /usr/local/openvpn_as/lib/python/ 
/usr/local/openvpn_as/bin/ovpn-init
}
function iptablesserv(){
add-iptable-rules=/etc/iptables/add-iptable-rules.sh
if test -f "$add-iptable-rules"; then
echo iptables is configured.
else
NIC=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
iptables -t nat -A POSTROUTING -s 10.69.1.0/24 -o gre1 -j MASQUERADE
iptables -t nat -A POSTROUTING -s 10.69.2.0/24 -o gre1 -j MASQUERADE
iptables -t nat -A POSTROUTING -s 10.69.3.0/24 -o gre1 -j MASQUERADE
iptables -t nat -A POSTROUTING -s 10.69.4.0/24 -o gre1 -j MASQUERADE
mkdir /etc/iptables/
touch /etc/iptables/add-iptable-rules.sh
touch /etc/iptables/rm-iptable-rules.sh
chmod +x /etc/iptables/add-iptable-rules.sh
chmod +x /etc/iptables/rm-iptable-rules.sh
echo -e "#!/bin/sh\n iptables -t nat -I POSTROUTING -s 10.69.1.0/24 -o gre1 -j MASQUERADE\n iptables -t nat -I POSTROUTING -s 10.69.2.0/24 -o gre1 -j MASQUERADE\n iptables -t nat -I POSTROUTING -s 10.69.3.0/24 -o gre1 -j MASQUERADE\n iptables -t nat -I POSTROUTING -s 10.69.4.0/24 -o gre1 -j MASQUERADE\n" |  tee -a /etc/iptables/add-iptable-rules.sh
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
sed -i -r '/.*net.ipv4.ip.*/s/^#//g' /etc/sysctl.conf #uncomment
sysctl -p
fi
}
function setupstie2site(){
clear
LOCALIP=$(curl -s https://api.ipify.org)
        until [[ $LOCALPOINT =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
        read -rp "Public address or hostname Of This Server: " -e -i "$LOCALIP" LOCALPOINT
done
REMOTEIP=$(curl -s https://api.ipify.org)
        until [[ $REMOTEPOINT =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
        read -rp "Public address or hostname Of Remote Server: " -e -i "$REMOTEIP" REMOTEPOINT
done
echo '100 GRE' >> /etc/iproute2/rt_tables
echo "[Unit]
Before=network.target
[Service]
Type=oneshot
ExecStart=ip tunnel add gre1 mode gre local $LOCALPOINT remote $REMOTEPOINT ttl 255
ExecStart=ip addr add 10.0.0.2/30 dev gre1
ExecStart=ip link set gre1 up
ExecStart=ip rule add from 10.0.0.0/30 table GRE
ExecStart=ip route add default via 10.0.0.1 table GRE
ExecStart=ip rule add from 10.69.1.0/24 table GRE
ExecStart=ip rule add from 10.69.2.0/24 table GRE
ExecStart=ip rule add from 10.69.3.0/24 table GRE
ExecStart=ip rule add from 10.69.4.0/24 table GRE
ExecStart=iptables -t nat -I POSTROUTING 1 -s 10.69.1.0/24 -o gre1 -j MASQUERADE
ExecStart=iptables -t nat -I POSTROUTING 1 -s 10.69.2.0/24 -o gre1 -j MASQUERADE
ExecStart=iptables -t nat -I POSTROUTING 1 -s 10.69.3.0/24 -o gre1 -j MASQUERADE
ExecStart=iptables -t nat -I POSTROUTING 1 -s 10.69.4.0/24 -o gre1 -j MASQUERADE
ExecStop=ip link delete gre1
ExecStop=ip route del default via 10.0.0.1 table GRE
ExecStop=ip rule del from 10.69.1.0/24 table GRE
ExecStop=ip rule del from 10.69.2.0/24 table GRE
ExecStop=ip rule del from 10.69.3.0/24 table GRE
ExecStop=ip rule del from 10.69.4.0/24 table GRE
ExecStop=iptables -t nat -D POSTROUTING 1 -s 10.69.1.0/24 -o gre1 -j MASQUERADE
ExecStop=iptables -t nat -D POSTROUTING 1 -s 10.69.2.0/24 -o gre1 -j MASQUERADE
ExecStop=iptables -t nat -D POSTROUTING 1 -s 10.69.3.0/24 -o gre1 -j MASQUERADE
ExecStop=iptables -t nat -D POSTROUTING 1 -s 10.69.4.0/24 -o gre1 -j MASQUERADE
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target" >/etc/systemd/system/gre-tunnel.service
systemctl daemon-reload
systemctl enable --now gre-tunnel
systemctl start gre-tunnel
echo "Enjoy it... :)"
sleep 2
}
function setupstie2siteAS(){
#!/bin/bash
clear
apt install anytun -y
mkdir -p /etc/tunnel
touch /etc/tunnel/start-covernet-tunnel.sh
touch /etc/tunnel/stop-covernet-tunnel.sh
chmod +x /etc/tunnel/start-covernet-tunnel.sh
chmod +x /etc/tunnel/stop-covernet-tunnel.sh
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
anytun -r $REMOTEPOINT -t tun -n 10.0.0.2/30 -c aes-ctr-256 -k aes-ctr-256 -E covernet -e left
echo '100 GRE' >> /etc/iproute2/rt_tables
ip rule add from 10.0.0.0/30 table GRE
ip rule add from 172.20.0.0/20 table GRE
ip route add default via 10.0.0.1 table GRE
iptables -t nat -I POSTROUTING 1 -s 172.0.0.0/20 -o tun0 -j MASQUERADE
EOF
cat > /etc/tunnel/stop-covernet-tunnel.sh <<EOF
#!/bin/bash
pkill -9 anytun
iptables -t nat -D POSTROUTING 1 -s 172.0.0.0/20 -o tun0 -j MASQUERADE
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
	echo -e "\e[0;31m1) Install OpenVPN Server With IBSng Config \e[0m"
	echo -e "\e[0;33m2) Install Cisco Any Connect Server With IBSng Config \e[0m"
	echo -e "\e[0;31m3) Install L2TP Server With IBSng Config \e[0m"
	echo -e "\e[0;33m4) Install PPTP Server With IBSng Config \e[0m"
	echo -e "\e[0;31m5) Install OpenVPNAS\e[0m"
	echo -e "\e[0;33m6) Install ShadowSocks Server \e[0m"
	echo -e "\e[0;31m7) Install WireGaurd Server \e[0m"
	echo
	echo -e "\e[0;35m8) Setup Site to Site Tunnel \e[0m"
	echo -e "\e[0;35m9) Setup Site to Site Tunnel AS \e[0m"
	echo
	echo -e "\e[0;32m10) Edit IBSng Configuration \e[0m"
	echo
	echo "0) Exit"
	echo
	read -rp "Select a number:" Selection

	if [ $Selection -gt 10 ]
	then
		echo "The variable is greater than 9."
		sleep 1s
	elif [ $Selection -eq 1 ]
	then
		installopenvpn
	elif [ $Selection -eq 2 ]
	then
		installocs
	elif [ $Selection -eq 3 ]
	then
		installl2tp
	elif [ $Selection -eq 4 ]
	then
		installpptp
	elif [ $Selection -eq 5 ]
	then
		installopenvpnas
	elif [ $Selection -eq 6 ]
	then
		installsocks5
	elif [ $Selection -eq 7 ]
	then
		installwiregaurd
	elif [ $Selection -eq 8 ]
	then
		setupstie2site
	elif [ $Selection -eq 9 ]
	then
		setupstie2siteAS
	elif [ $Selection -eq 10 ]
	then
		editras
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
