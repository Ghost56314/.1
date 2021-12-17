#!/bin/bash
# shellcheck disable=SC1091,SC2164,SC2034,SC1072,SC1073,SC1009
function installopenvpn(){  
    	function isRoot() {
    		if [ "$EUID" -ne 0 ]; then
    			return 1
    		fi
    	}
    	
    	function tunAvailable() {
    		if [ ! -e /dev/net/tun ]; then
    			return 1
    		fi
    	}
    	
    	function checkOS() {
    		if [[ -e /etc/debian_version ]]; then
    			OS="debian"
    			source /etc/os-release
    	
    			if [[ $ID == "debian" || $ID == "raspbian" ]]; then
    				if [[ $VERSION_ID -lt 9 ]]; then
    					echo "⚠️ Your version of Debian is not supported."
    					echo ""
    					echo "However, if you're using Debian >= 9 or unstable/testing then you can continue, at your own risk."
    					echo ""
    					until [[ $CONTINUE =~ (y|n) ]]; do
    						read -rp "Continue? [y/n]: " -e CONTINUE
    					done
    					if [[ $CONTINUE == "n" ]]; then
    						exit 1
    					fi
    				fi
    			elif [[ $ID == "ubuntu" ]]; then
    				OS="ubuntu"
    				MAJOR_UBUNTU_VERSION=$(echo "$VERSION_ID" | cut -d '.' -f1)
    				if [[ $MAJOR_UBUNTU_VERSION -lt 16 ]]; then
    					echo "⚠️ Your version of Ubuntu is not supported."
    					echo ""
    					echo "However, if you're using Ubuntu >= 16.04 or beta, then you can continue, at your own risk."
    					echo ""
    					until [[ $CONTINUE =~ (y|n) ]]; do
    						read -rp "Continue? [y/n]: " -e CONTINUE
    					done
    					if [[ $CONTINUE == "n" ]]; then
    						exit 1
    					fi
    				fi
    			fi
    		elif [[ -e /etc/system-release ]]; then
    			source /etc/os-release
    			if [[ $ID == "fedora" || $ID_LIKE == "fedora" ]]; then
    				OS="fedora"
    			fi
    			if [[ $ID == "centos" || $ID == "rocky" || $ID == "almalinux" ]]; then
    				OS="centos"
    				if [[ ! $VERSION_ID =~ (7|8) ]]; then
    					echo "⚠️ Your version of CentOS is not supported."
    					echo ""
    					echo "The script only support CentOS 7 and CentOS 8."
    					echo ""
    					exit 1
    				fi
    			fi
    			if [[ $ID == "ol" ]]; then
    				OS="oracle"
    				if [[ ! $VERSION_ID =~ (8) ]]; then
    					echo "Your version of Oracle Linux is not supported."
    					echo ""
    					echo "The script only support Oracle Linux 8."
    					exit 1
    				fi
    			fi
    			if [[ $ID == "amzn" ]]; then
    				OS="amzn"
    				if [[ $VERSION_ID != "2" ]]; then
    					echo "⚠️ Your version of Amazon Linux is not supported."
    					echo ""
    					echo "The script only support Amazon Linux 2."
    					echo ""
    					exit 1
    				fi
    			fi
    		elif [[ -e /etc/arch-release ]]; then
    			OS=arch
    		else
    			echo "Looks like you aren't running this installer on a Debian, Ubuntu, Fedora, CentOS, Amazon Linux 2, Oracle Linux 8 or Arch Linux system"
    			exit 1
    		fi
    	}
    	
    	function initialCheck() {
    		if ! isRoot; then
    			echo "Sorry, you need to run this as root"
    			exit 1
    		fi
    		if ! tunAvailable; then
    			echo "TUN is not available"
    			exit 1
    		fi
    		checkOS
    	}
    	
    	function installUnbound() {
    		# If Unbound isn't installed, install it
    		if [[ ! -e /etc/unbound/unbound.conf ]]; then
    	
    			if [[ $OS =~ (debian|ubuntu) ]]; then
    				apt-get install -y unbound
    	
    				# Configuration
    				echo 'interface: 10.8.0.1
    	access-control: 10.8.0.1/24 allow
    	hide-identity: yes
    	hide-version: yes
    	use-caps-for-id: yes
    	prefetch: yes' >>/etc/unbound/unbound.conf
    	
    			elif [[ $OS =~ (centos|amzn|oracle) ]]; then
    				yum install -y unbound
    	
    				# Configuration
    				sed -i 's|# interface: 0.0.0.0$|interface: 10.8.0.1|' /etc/unbound/unbound.conf
    				sed -i 's|# access-control: 127.0.0.0/8 allow|access-control: 10.8.0.1/24 allow|' /etc/unbound/unbound.conf
    				sed -i 's|# hide-identity: no|hide-identity: yes|' /etc/unbound/unbound.conf
    				sed -i 's|# hide-version: no|hide-version: yes|' /etc/unbound/unbound.conf
    				sed -i 's|use-caps-for-id: no|use-caps-for-id: yes|' /etc/unbound/unbound.conf
    	
    			elif [[ $OS == "fedora" ]]; then
    				dnf install -y unbound
    	
    				# Configuration
    				sed -i 's|# interface: 0.0.0.0$|interface: 10.8.0.1|' /etc/unbound/unbound.conf
    				sed -i 's|# access-control: 127.0.0.0/8 allow|access-control: 10.8.0.1/24 allow|' /etc/unbound/unbound.conf
    				sed -i 's|# hide-identity: no|hide-identity: yes|' /etc/unbound/unbound.conf
    				sed -i 's|# hide-version: no|hide-version: yes|' /etc/unbound/unbound.conf
    				sed -i 's|# use-caps-for-id: no|use-caps-for-id: yes|' /etc/unbound/unbound.conf
    	
    			elif [[ $OS == "arch" ]]; then
    				pacman -Syu --noconfirm unbound
    	
    				# Get root servers list
    				curl -o /etc/unbound/root.hints https://www.internic.net/domain/named.cache
    	
    				if [[ ! -f /etc/unbound/unbound.conf.old ]]; then
    					mv /etc/unbound/unbound.conf /etc/unbound/unbound.conf.old
    				fi
    	
    				echo 'server:
    		use-syslog: yes
    		do-daemonize: no
    		username: "unbound"
    		directory: "/etc/unbound"
    		trust-anchor-file: trusted-key.key
    		root-hints: root.hints
    		interface: 10.8.0.1
    		access-control: 10.8.0.1/24 allow
    		port: 53
    		num-threads: 2
    		use-caps-for-id: yes
    		harden-glue: yes
    		hide-identity: yes
    		hide-version: yes
    		qname-minimisation: yes
    		prefetch: yes' >/etc/unbound/unbound.conf
    			fi
    	
    			# IPv6 DNS for all OS
    			if [[ $IPV6_SUPPORT == 'y' ]]; then
    				echo 'interface: fd42:42:42:42::1
    	access-control: fd42:42:42:42::/112 allow' >>/etc/unbound/unbound.conf
    			fi
    	
    			if [[ ! $OS =~ (fedora|centos|amzn|oracle) ]]; then
    				# DNS Rebinding fix
    				echo "private-address: 10.0.0.0/8
    	private-address: fd42:42:42:42::/112
    	private-address: 172.16.0.0/12
    	private-address: 192.168.0.0/16
    	private-address: 169.254.0.0/16
    	private-address: fd00::/8
    	private-address: fe80::/10
    	private-address: 127.0.0.0/8
    	private-address: ::ffff:0:0/96" >>/etc/unbound/unbound.conf
    			fi
    		else # Unbound is already installed
    			echo 'include: /etc/unbound/openvpn.conf' >>/etc/unbound/unbound.conf
    	
    			# Add Unbound 'server' for the OpenVPN subnet
    			echo 'server:
    	interface: 10.8.0.1
    	access-control: 10.8.0.1/24 allow
    	hide-identity: yes
    	hide-version: yes
    	use-caps-for-id: yes
    	prefetch: yes
    	private-address: 10.0.0.0/8
    	private-address: fd42:42:42:42::/112
    	private-address: 172.16.0.0/12
    	private-address: 192.168.0.0/16
    	private-address: 169.254.0.0/16
    	private-address: fd00::/8
    	private-address: fe80::/10
    	private-address: 127.0.0.0/8
    	private-address: ::ffff:0:0/96' >/etc/unbound/openvpn.conf
    			if [[ $IPV6_SUPPORT == 'y' ]]; then
    				echo 'interface: fd42:42:42:42::1
    	access-control: fd42:42:42:42::/112 allow' >>/etc/unbound/openvpn.conf
    			fi
    		fi
    	
    		systemctl enable unbound
    		systemctl restart unbound
    	}
    	
    	function installQuestions() {
    		echo "Welcome to the OpenVPN installer!"
    		echo "The git repository is available at: https://github.com/angristan/openvpn-install"
    		echo ""
    	
    		echo "I need to ask you a few questions before starting the setup."
    		echo "You can leave the default options and just press enter if you are ok with them."
    		echo ""
    		echo "I need to know the IPv4 address of the network interface you want OpenVPN listening to."
    		echo "Unless your server is behind NAT, it should be your public IPv4 address."
    	
    		# Detect public IPv4 address and pre-fill for the user
    		IP=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | head -1)
    	
    		if [[ -z $IP ]]; then
    			# Detect public IPv6 address
    			IP=$(ip -6 addr | sed -ne 's|^.* inet6 \([^/]*\)/.* scope global.*$|\1|p' | head -1)
    		fi
    		APPROVE_IP=${APPROVE_IP:-n}
    		if [[ $APPROVE_IP =~ n ]]; then
    			read -rp "IP address: " -e -i "$IP" IP
    		fi
    		# If $IP is a private IP address, the server must be behind NAT
    		if echo "$IP" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
    			echo ""
    			echo "It seems this server is behind NAT. What is its public IPv4 address or hostname?"
    			echo "We need it for the clients to connect to the server."
    	
    			PUBLICIP=$(curl -s https://api.ipify.org)
    			until [[ $ENDPOINT != "" ]]; do
    				read -rp "Public IPv4 address or hostname: " -e -i "$PUBLICIP" ENDPOINT
    			done
    		fi
    	
    		echo ""
    		echo "Checking for IPv6 connectivity..."
    		echo ""
    		# "ping6" and "ping -6" availability varies depending on the distribution
    		if type ping6 >/dev/null 2>&1; then
    			PING6="ping6 -c3 ipv6.google.com > /dev/null 2>&1"
    		else
    			PING6="ping -6 -c3 ipv6.google.com > /dev/null 2>&1"
    		fi
    		if eval "$PING6"; then
    			echo "Your host appears to have IPv6 connectivity."
    			SUGGESTION="y"
    		else
    			echo "Your host does not appear to have IPv6 connectivity."
    			SUGGESTION="n"
    		fi
    		echo ""
    		# Ask the user if they want to enable IPv6 regardless its availability.
    		until [[ $IPV6_SUPPORT =~ (y|n) ]]; do
    			read -rp "Do you want to enable IPv6 support (NAT)? [y/n]: " -e -i $SUGGESTION IPV6_SUPPORT
    		done
    		echo ""
    		echo "What port do you want OpenVPN to listen to?"
    		echo "   1) Default: 1194"
    		echo "   2) Custom"
    		echo "   3) Random [49152-65535]"
    		until [[ $PORT_CHOICE =~ ^[1-3]$ ]]; do
    			read -rp "Port choice [1-3]: " -e -i 1 PORT_CHOICE
    		done
    		case $PORT_CHOICE in
    		1)
    			PORT="1194"
    			;;
    		2)
    			until [[ $PORT =~ ^[0-9]+$ ]] && [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ]; do
    				read -rp "Custom port [1-65535]: " -e -i 1194 PORT
    			done
    			;;
    		3)
    			# Generate random number within private ports range
    			PORT=$(shuf -i49152-65535 -n1)
    			echo "Random Port: $PORT"
    			;;
    		esac
    		echo ""
    		echo "What protocol do you want OpenVPN to use?"
    		echo "UDP is faster. Unless it is not available, you shouldn't use TCP."
    		echo "   1) UDP"
    		echo "   2) TCP"
    		until [[ $PROTOCOL_CHOICE =~ ^[1-2]$ ]]; do
    			read -rp "Protocol [1-2]: " -e -i 1 PROTOCOL_CHOICE
    		done
    		case $PROTOCOL_CHOICE in
    		1)
    			PROTOCOL="udp"
    			;;
    		2)
    			PROTOCOL="tcp"
    			;;
    		esac
    		echo ""
    		echo "What DNS resolvers do you want to use with the VPN?"
    		echo "   1) Current system resolvers (from /etc/resolv.conf)"
    		echo "   2) Self-hosted DNS Resolver (Unbound)"
    		echo "   3) Cloudflare (Anycast: worldwide)"
    		echo "   4) Quad9 (Anycast: worldwide)"
    		echo "   5) Quad9 uncensored (Anycast: worldwide)"
    		echo "   6) FDN (France)"
    		echo "   7) DNS.WATCH (Germany)"
    		echo "   8) OpenDNS (Anycast: worldwide)"
    		echo "   9) Google (Anycast: worldwide)"
    		echo "   10) Yandex Basic (Russia)"
    		echo "   11) AdGuard DNS (Anycast: worldwide)"
    		echo "   12) NextDNS (Anycast: worldwide)"
    		echo "   13) Custom"
    		until [[ $DNS =~ ^[0-9]+$ ]] && [ "$DNS" -ge 1 ] && [ "$DNS" -le 13 ]; do
    			read -rp "DNS [1-12]: " -e -i 11 DNS
    			if [[ $DNS == 2 ]] && [[ -e /etc/unbound/unbound.conf ]]; then
    				echo ""
    				echo "Unbound is already installed."
    				echo "You can allow the script to configure it in order to use it from your OpenVPN clients"
    				echo "We will simply add a second server to /etc/unbound/unbound.conf for the OpenVPN subnet."
    				echo "No changes are made to the current configuration."
    				echo ""
    	
    				until [[ $CONTINUE =~ (y|n) ]]; do
    					read -rp "Apply configuration changes to Unbound? [y/n]: " -e CONTINUE
    				done
    				if [[ $CONTINUE == "n" ]]; then
    					# Break the loop and cleanup
    					unset DNS
    					unset CONTINUE
    				fi
    			elif [[ $DNS == "13" ]]; then
    				until [[ $DNS1 =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
    					read -rp "Primary DNS: " -e DNS1
    				done
    				until [[ $DNS2 =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
    					read -rp "Secondary DNS (optional): " -e DNS2
    					if [[ $DNS2 == "" ]]; then
    						break
    					fi
    				done
    			fi
    		done
    		echo ""
    		echo "Do you want to use compression? It is not recommended since the VORACLE attack make use of it."
    		until [[ $COMPRESSION_ENABLED =~ (y|n) ]]; do
    			read -rp"Enable compression? [y/n]: " -e -i n COMPRESSION_ENABLED
    		done
    		if [[ $COMPRESSION_ENABLED == "y" ]]; then
    			echo "Choose which compression algorithm you want to use: (they are ordered by efficiency)"
    			echo "   1) LZ4-v2"
    			echo "   2) LZ4"
    			echo "   3) LZ0"
    			until [[ $COMPRESSION_CHOICE =~ ^[1-3]$ ]]; do
    				read -rp"Compression algorithm [1-3]: " -e -i 1 COMPRESSION_CHOICE
    			done
    			case $COMPRESSION_CHOICE in
    			1)
    				COMPRESSION_ALG="lz4-v2"
    				;;
    			2)
    				COMPRESSION_ALG="lz4"
    				;;
    			3)
    				COMPRESSION_ALG="lzo"
    				;;
    			esac
    		fi
    		echo ""
    		echo "Do you want to customize encryption settings?"
    		echo "Unless you know what you're doing, you should stick with the default parameters provided by the script."
    		echo "Note that whatever you choose, all the choices presented in the script are safe. (Unlike OpenVPN's defaults)"
    		echo "See https://github.com/angristan/openvpn-install#security-and-encryption to learn more."
    		echo ""
    		until [[ $CUSTOMIZE_ENC =~ (y|n) ]]; do
    			read -rp "Customize encryption settings? [y/n]: " -e -i n CUSTOMIZE_ENC
    		done
    		if [[ $CUSTOMIZE_ENC == "n" ]]; then
    			# Use default, sane and fast parameters
    			CIPHER="AES-128-GCM"
    			CERT_TYPE="1" # ECDSA
    			CERT_CURVE="prime256v1"
    			CC_CIPHER="TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"
    			DH_TYPE="1" # ECDH
    			DH_CURVE="prime256v1"
    			HMAC_ALG="SHA256"
    			TLS_SIG="1" # tls-crypt
    		else
    			echo ""
    			echo "Choose which cipher you want to use for the data channel:"
    			echo "   1) AES-128-GCM (recommended)"
    			echo "   2) AES-192-GCM"
    			echo "   3) AES-256-GCM"
    			echo "   4) AES-128-CBC"
    			echo "   5) AES-192-CBC"
    			echo "   6) AES-256-CBC"
    			until [[ $CIPHER_CHOICE =~ ^[1-6]$ ]]; do
    				read -rp "Cipher [1-6]: " -e -i 1 CIPHER_CHOICE
    			done
    			case $CIPHER_CHOICE in
    			1)
    				CIPHER="AES-128-GCM"
    				;;
    			2)
    				CIPHER="AES-192-GCM"
    				;;
    			3)
    				CIPHER="AES-256-GCM"
    				;;
    			4)
    				CIPHER="AES-128-CBC"
    				;;
    			5)
    				CIPHER="AES-192-CBC"
    				;;
    			6)
    				CIPHER="AES-256-CBC"
    				;;
    			esac
    			echo ""
    			echo "Choose what kind of certificate you want to use:"
    			echo "   1) ECDSA (recommended)"
    			echo "   2) RSA"
    			until [[ $CERT_TYPE =~ ^[1-2]$ ]]; do
    				read -rp"Certificate key type [1-2]: " -e -i 1 CERT_TYPE
    			done
    			case $CERT_TYPE in
    			1)
    				echo ""
    				echo "Choose which curve you want to use for the certificate's key:"
    				echo "   1) prime256v1 (recommended)"
    				echo "   2) secp384r1"
    				echo "   3) secp521r1"
    				until [[ $CERT_CURVE_CHOICE =~ ^[1-3]$ ]]; do
    					read -rp"Curve [1-3]: " -e -i 1 CERT_CURVE_CHOICE
    				done
    				case $CERT_CURVE_CHOICE in
    				1)
    					CERT_CURVE="prime256v1"
    					;;
    				2)
    					CERT_CURVE="secp384r1"
    					;;
    				3)
    					CERT_CURVE="secp521r1"
    					;;
    				esac
    				;;
    			2)
    				echo ""
    				echo "Choose which size you want to use for the certificate's RSA key:"
    				echo "   1) 2048 bits (recommended)"
    				echo "   2) 3072 bits"
    				echo "   3) 4096 bits"
    				until [[ $RSA_KEY_SIZE_CHOICE =~ ^[1-3]$ ]]; do
    					read -rp "RSA key size [1-3]: " -e -i 1 RSA_KEY_SIZE_CHOICE
    				done
    				case $RSA_KEY_SIZE_CHOICE in
    				1)
    					RSA_KEY_SIZE="2048"
    					;;
    				2)
    					RSA_KEY_SIZE="3072"
    					;;
    				3)
    					RSA_KEY_SIZE="4096"
    					;;
    				esac
    				;;
    			esac
    			echo ""
    			echo "Choose which cipher you want to use for the control channel:"
    			case $CERT_TYPE in
    			1)
    				echo "   1) ECDHE-ECDSA-AES-128-GCM-SHA256 (recommended)"
    				echo "   2) ECDHE-ECDSA-AES-256-GCM-SHA384"
    				until [[ $CC_CIPHER_CHOICE =~ ^[1-2]$ ]]; do
    					read -rp"Control channel cipher [1-2]: " -e -i 1 CC_CIPHER_CHOICE
    				done
    				case $CC_CIPHER_CHOICE in
    				1)
    					CC_CIPHER="TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"
    					;;
    				2)
    					CC_CIPHER="TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384"
    					;;
    				esac
    				;;
    			2)
    				echo "   1) ECDHE-RSA-AES-128-GCM-SHA256 (recommended)"
    				echo "   2) ECDHE-RSA-AES-256-GCM-SHA384"
    				until [[ $CC_CIPHER_CHOICE =~ ^[1-2]$ ]]; do
    					read -rp"Control channel cipher [1-2]: " -e -i 1 CC_CIPHER_CHOICE
    				done
    				case $CC_CIPHER_CHOICE in
    				1)
    					CC_CIPHER="TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256"
    					;;
    				2)
    					CC_CIPHER="TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384"
    					;;
    				esac
    				;;
    			esac
    			echo ""
    			echo "Choose what kind of Diffie-Hellman key you want to use:"
    			echo "   1) ECDH (recommended)"
    			echo "   2) DH"
    			until [[ $DH_TYPE =~ [1-2] ]]; do
    				read -rp"DH key type [1-2]: " -e -i 1 DH_TYPE
    			done
    			case $DH_TYPE in
    			1)
    				echo ""
    				echo "Choose which curve you want to use for the ECDH key:"
    				echo "   1) prime256v1 (recommended)"
    				echo "   2) secp384r1"
    				echo "   3) secp521r1"
    				while [[ $DH_CURVE_CHOICE != "1" && $DH_CURVE_CHOICE != "2" && $DH_CURVE_CHOICE != "3" ]]; do
    					read -rp"Curve [1-3]: " -e -i 1 DH_CURVE_CHOICE
    				done
    				case $DH_CURVE_CHOICE in
    				1)
    					DH_CURVE="prime256v1"
    					;;
    				2)
    					DH_CURVE="secp384r1"
    					;;
    				3)
    					DH_CURVE="secp521r1"
    					;;
    				esac
    				;;
    			2)
    				echo ""
    				echo "Choose what size of Diffie-Hellman key you want to use:"
    				echo "   1) 2048 bits (recommended)"
    				echo "   2) 3072 bits"
    				echo "   3) 4096 bits"
    				until [[ $DH_KEY_SIZE_CHOICE =~ ^[1-3]$ ]]; do
    					read -rp "DH key size [1-3]: " -e -i 1 DH_KEY_SIZE_CHOICE
    				done
    				case $DH_KEY_SIZE_CHOICE in
    				1)
    					DH_KEY_SIZE="2048"
    					;;
    				2)
    					DH_KEY_SIZE="3072"
    					;;
    				3)
    					DH_KEY_SIZE="4096"
    					;;
    				esac
    				;;
    			esac
    			echo ""
    			# The "auth" options behaves differently with AEAD ciphers
    			if [[ $CIPHER =~ CBC$ ]]; then
    				echo "The digest algorithm authenticates data channel packets and tls-auth packets from the control channel."
    			elif [[ $CIPHER =~ GCM$ ]]; then
    				echo "The digest algorithm authenticates tls-auth packets from the control channel."
    			fi
    			echo "Which digest algorithm do you want to use for HMAC?"
    			echo "   1) SHA-256 (recommended)"
    			echo "   2) SHA-384"
    			echo "   3) SHA-512"
    			until [[ $HMAC_ALG_CHOICE =~ ^[1-3]$ ]]; do
    				read -rp "Digest algorithm [1-3]: " -e -i 1 HMAC_ALG_CHOICE
    			done
    			case $HMAC_ALG_CHOICE in
    			1)
    				HMAC_ALG="SHA256"
    				;;
    			2)
    				HMAC_ALG="SHA384"
    				;;
    			3)
    				HMAC_ALG="SHA512"
    				;;
    			esac
    			echo ""
    			echo "You can add an additional layer of security to the control channel with tls-auth and tls-crypt"
    			echo "tls-auth authenticates the packets, while tls-crypt authenticate and encrypt them."
    			echo "   1) tls-crypt (recommended)"
    			echo "   2) tls-auth"
    			until [[ $TLS_SIG =~ [1-2] ]]; do
    				read -rp "Control channel additional security mechanism [1-2]: " -e -i 1 TLS_SIG
    			done
    		fi
    		echo ""
    		echo "Okay, that was all I needed. We are ready to setup your OpenVPN server now."
    		echo "You will be able to generate a client at the end of the installation."
    		APPROVE_INSTALL=${APPROVE_INSTALL:-n}
    		if [[ $APPROVE_INSTALL =~ n ]]; then
    			read -n1 -r -p "Press any key to continue..."
    		fi
    	}
    	
    	function installOpenVPN() {
    		if [[ $AUTO_INSTALL == "y" ]]; then
    			# Set default choices so that no questions will be asked.
    			APPROVE_INSTALL=${APPROVE_INSTALL:-y}
    			APPROVE_IP=${APPROVE_IP:-y}
    			IPV6_SUPPORT=${IPV6_SUPPORT:-n}
    			PORT_CHOICE=${PORT_CHOICE:-1}
    			PROTOCOL_CHOICE=${PROTOCOL_CHOICE:-1}
    			DNS=${DNS:-1}
    			COMPRESSION_ENABLED=${COMPRESSION_ENABLED:-n}
    			CUSTOMIZE_ENC=${CUSTOMIZE_ENC:-n}
    			CLIENT=${CLIENT:-client}
    			PASS=${PASS:-1}
    			CONTINUE=${CONTINUE:-y}
    	
    			# Behind NAT, we'll default to the publicly reachable IPv4/IPv6.
    			if [[ $IPV6_SUPPORT == "y" ]]; then
    				PUBLIC_IP=$(curl https://ifconfig.co)
    			else
    				PUBLIC_IP=$(curl -4 https://ifconfig.co)
    			fi
    			ENDPOINT=${ENDPOINT:-$PUBLIC_IP}
    		fi
    	
    		# Run setup questions first, and set other variales if auto-install
    		installQuestions
    	
    		# Get the "public" interface from the default route
    		NIC=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
    		if [[ -z $NIC ]] && [[ $IPV6_SUPPORT == 'y' ]]; then
    			NIC=$(ip -6 route show default | sed -ne 's/^default .* dev \([^ ]*\) .*$/\1/p')
    		fi
    	
    		# $NIC can not be empty for script rm-openvpn-rules.sh
    		if [[ -z $NIC ]]; then
    			echo
    			echo "Can not detect public interface."
    			echo "This needs for setup MASQUERADE."
    			until [[ $CONTINUE =~ (y|n) ]]; do
    				read -rp "Continue? [y/n]: " -e CONTINUE
    			done
    			if [[ $CONTINUE == "n" ]]; then
    				exit 1
    			fi
    		fi
    	
    		# If OpenVPN isn't installed yet, install it. This script is more-or-less
    		# idempotent on multiple runs, but will only install OpenVPN from upstream
    		# the first time.
    		if [[ ! -e /etc/openvpn/server.conf ]]; then
    			if [[ $OS =~ (debian|ubuntu) ]]; then
    				apt-get update
    				apt-get -y install ca-certificates gnupg
    				# We add the OpenVPN repo to get the latest version.
    				if [[ $VERSION_ID == "16.04" ]]; then
    					echo "deb http://build.openvpn.net/debian/openvpn/stable xenial main" >/etc/apt/sources.list.d/openvpn.list
    					wget -O - https://swupdate.openvpn.net/repos/repo-public.gpg | apt-key add -
    					apt-get update
    				fi
    				# Ubuntu > 16.04 and Debian > 8 have OpenVPN >= 2.4 without the need of a third party repository.
    				apt-get install -y openvpn iptables openssl wget ca-certificates curl
    			elif [[ $OS == 'centos' ]]; then
    				yum install -y epel-release
    				yum install -y openvpn iptables openssl wget ca-certificates curl tar 'policycoreutils-python*'
    			elif [[ $OS == 'oracle' ]]; then
    				yum install -y 'oracle-epel-release-*'
    				yum install -y openvpn iptables openssl wget ca-certificates curl tar 'policycoreutils-python*'
    			elif [[ $OS == 'amzn' ]]; then
    				amazon-linux-extras install -y epel
    				yum install -y openvpn iptables openssl wget ca-certificates curl
    			elif [[ $OS == 'fedora' ]]; then
    				dnf install -y openvpn iptables openssl wget ca-certificates curl policycoreutils-python-utils
    			elif [[ $OS == 'arch' ]]; then
    				# Install required dependencies and upgrade the system
    				pacman --needed --noconfirm -Syu openvpn iptables openssl wget ca-certificates curl
    			fi
    			# An old version of easy-rsa was available by default in some openvpn packages
    			if [[ -d /etc/openvpn/easy-rsa/ ]]; then
    				rm -rf /etc/openvpn/easy-rsa/
    			fi
    		fi
    	
    		# Find out if the machine uses nogroup or nobody for the permissionless group
    		if grep -qs "^nogroup:" /etc/group; then
    			NOGROUP=nogroup
    		else
    			NOGROUP=nobody
    		fi
    	
    		# Install the latest version of easy-rsa from source, if not already installed.
    		if [[ ! -d /etc/openvpn/easy-rsa/ ]]; then
    			local version="3.0.7"
    			wget -O ~/easy-rsa.tgz https://github.com/OpenVPN/easy-rsa/releases/download/v${version}/EasyRSA-${version}.tgz
    			mkdir -p /etc/openvpn/easy-rsa
    			tar xzf ~/easy-rsa.tgz --strip-components=1 --directory /etc/openvpn/easy-rsa
    			rm -f ~/easy-rsa.tgz
    	
    			cd /etc/openvpn/easy-rsa/ || return
    			case $CERT_TYPE in
    			1)
    				echo "set_var EASYRSA_ALGO ec" >vars
    				echo "set_var EASYRSA_CURVE $CERT_CURVE" >>vars
    				;;
    			2)
    				echo "set_var EASYRSA_KEY_SIZE $RSA_KEY_SIZE" >vars
    				;;
    			esac
    	
    			# Generate a random, alphanumeric identifier of 16 characters for CN and one for server name
    			SERVER_CN="cn_$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)"
    			echo "$SERVER_CN" >SERVER_CN_GENERATED
    			SERVER_NAME="server_$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)"
    			echo "$SERVER_NAME" >SERVER_NAME_GENERATED
    	
    			echo "set_var EASYRSA_REQ_CN $SERVER_CN" >>vars
    	
    			# Create the PKI, set up the CA, the DH params and the server certificate
    			./easyrsa init-pki
    			./easyrsa --batch build-ca nopass
    	
    			if [[ $DH_TYPE == "2" ]]; then
    				# ECDH keys are generated on-the-fly so we don't need to generate them beforehand
    				openssl dhparam -out dh.pem $DH_KEY_SIZE
    			fi
    	
    			./easyrsa build-server-full "$SERVER_NAME" nopass
    			EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
    	
    			case $TLS_SIG in
    			1)
    				# Generate tls-crypt key
    				openvpn --genkey --secret /etc/openvpn/tls-crypt.key
    				;;
    			2)
    				# Generate tls-auth key
    				openvpn --genkey --secret /etc/openvpn/tls-auth.key
    				;;
    			esac
    		else
    			# If easy-rsa is already installed, grab the generated SERVER_NAME
    			# for client configs
    			cd /etc/openvpn/easy-rsa/ || return
    			SERVER_NAME=$(cat SERVER_NAME_GENERATED)
    		fi
    	
    		# Move all the generated files
    		cp pki/ca.crt pki/private/ca.key "pki/issued/$SERVER_NAME.crt" "pki/private/$SERVER_NAME.key" /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn
    		if [[ $DH_TYPE == "2" ]]; then
    			cp dh.pem /etc/openvpn
    		fi
    	
    		# Make cert revocation list readable for non-root
    		chmod 644 /etc/openvpn/crl.pem
    	
    		# Generate server.conf
    		echo "port $PORT" >/etc/openvpn/server.conf
    		if [[ $IPV6_SUPPORT == 'n' ]]; then
    			echo "proto $PROTOCOL" >>/etc/openvpn/server.conf
    		elif [[ $IPV6_SUPPORT == 'y' ]]; then
    			echo "proto ${PROTOCOL}6" >>/etc/openvpn/server.conf
    		fi
    	
    		echo "dev tun
    	user nobody
    	group $NOGROUP
    	persist-key
    	persist-tun
	duplicate-cn
    	keepalive 10 120
    	topology subnet
    	server 10.8.0.0 255.255.255.0
    	ifconfig-pool-persist ipp.txt" >>/etc/openvpn/server.conf
    	
    		# DNS resolvers
    		case $DNS in
    		1) # Current system resolvers
    			# Locate the proper resolv.conf
    			# Needed for systems running systemd-resolved
    			if grep -q "127.0.0.53" "/etc/resolv.conf"; then
    				RESOLVCONF='/run/systemd/resolve/resolv.conf'
    			else
    				RESOLVCONF='/etc/resolv.conf'
    			fi
    			# Obtain the resolvers from resolv.conf and use them for OpenVPN
    			sed -ne 's/^nameserver[[:space:]]\+\([^[:space:]]\+\).*$/\1/p' $RESOLVCONF | while read -r line; do
    				# Copy, if it's a IPv4 |or| if IPv6 is enabled, IPv4/IPv6 does not matter
    				if [[ $line =~ ^[0-9.]*$ ]] || [[ $IPV6_SUPPORT == 'y' ]]; then
    					echo "push \"dhcp-option DNS $line\"" >>/etc/openvpn/server.conf
    				fi
    			done
    			;;
    		2) # Self-hosted DNS resolver (Unbound)
    			echo 'push "dhcp-option DNS 10.8.0.1"' >>/etc/openvpn/server.conf
    			if [[ $IPV6_SUPPORT == 'y' ]]; then
    				echo 'push "dhcp-option DNS fd42:42:42:42::1"' >>/etc/openvpn/server.conf
    			fi
    			;;
    		3) # Cloudflare
    			echo 'push "dhcp-option DNS 1.0.0.1"' >>/etc/openvpn/server.conf
    			echo 'push "dhcp-option DNS 1.1.1.1"' >>/etc/openvpn/server.conf
    			;;
    		4) # Quad9
    			echo 'push "dhcp-option DNS 9.9.9.9"' >>/etc/openvpn/server.conf
    			echo 'push "dhcp-option DNS 149.112.112.112"' >>/etc/openvpn/server.conf
    			;;
    		5) # Quad9 uncensored
    			echo 'push "dhcp-option DNS 9.9.9.10"' >>/etc/openvpn/server.conf
    			echo 'push "dhcp-option DNS 149.112.112.10"' >>/etc/openvpn/server.conf
    			;;
    		6) # FDN
    			echo 'push "dhcp-option DNS 80.67.169.40"' >>/etc/openvpn/server.conf
    			echo 'push "dhcp-option DNS 80.67.169.12"' >>/etc/openvpn/server.conf
    			;;
    		7) # DNS.WATCH
    			echo 'push "dhcp-option DNS 84.200.69.80"' >>/etc/openvpn/server.conf
    			echo 'push "dhcp-option DNS 84.200.70.40"' >>/etc/openvpn/server.conf
    			;;
    		8) # OpenDNS
    			echo 'push "dhcp-option DNS 208.67.222.222"' >>/etc/openvpn/server.conf
    			echo 'push "dhcp-option DNS 208.67.220.220"' >>/etc/openvpn/server.conf
    			;;
    		9) # Google
    			echo 'push "dhcp-option DNS 8.8.8.8"' >>/etc/openvpn/server.conf
    			echo 'push "dhcp-option DNS 8.8.4.4"' >>/etc/openvpn/server.conf
    			;;
    		10) # Yandex Basic
    			echo 'push "dhcp-option DNS 77.88.8.8"' >>/etc/openvpn/server.conf
    			echo 'push "dhcp-option DNS 77.88.8.1"' >>/etc/openvpn/server.conf
    			;;
    		11) # AdGuard DNS
    			echo 'push "dhcp-option DNS 94.140.14.14"' >>/etc/openvpn/server.conf
    			echo 'push "dhcp-option DNS 94.140.15.15"' >>/etc/openvpn/server.conf
    			;;
    		12) # NextDNS
    			echo 'push "dhcp-option DNS 45.90.28.167"' >>/etc/openvpn/server.conf
    			echo 'push "dhcp-option DNS 45.90.30.167"' >>/etc/openvpn/server.conf
    			;;
    		13) # Custom DNS
    			echo "push \"dhcp-option DNS $DNS1\"" >>/etc/openvpn/server.conf
    			if [[ $DNS2 != "" ]]; then
    				echo "push \"dhcp-option DNS $DNS2\"" >>/etc/openvpn/server.conf
    			fi
    			;;
    		esac
    		echo 'push "redirect-gateway def1 bypass-dhcp"' >>/etc/openvpn/server.conf
    	
    		# IPv6 network settings if needed
    		if [[ $IPV6_SUPPORT == 'y' ]]; then
    			echo 'server-ipv6 fd42:42:42:42::/112
    	tun-ipv6
    	push tun-ipv6
    	push "route-ipv6 2000::/3"
    	push "redirect-gateway ipv6"' >>/etc/openvpn/server.conf
    		fi
    	
    		if [[ $COMPRESSION_ENABLED == "y" ]]; then
    			echo "compress $COMPRESSION_ALG" >>/etc/openvpn/server.conf
    		fi
    	
    		if [[ $DH_TYPE == "1" ]]; then
    			echo "dh none" >>/etc/openvpn/server.conf
    			echo "ecdh-curve $DH_CURVE" >>/etc/openvpn/server.conf
    		elif [[ $DH_TYPE == "2" ]]; then
    			echo "dh dh.pem" >>/etc/openvpn/server.conf
    		fi
    	
    		case $TLS_SIG in
    		1)
    			echo "tls-crypt tls-crypt.key" >>/etc/openvpn/server.conf
    			;;
    		2)
    			echo "tls-auth tls-auth.key 0" >>/etc/openvpn/server.conf
    			;;
    		esac
    	
    		echo "crl-verify crl.pem
    	ca ca.crt
    	cert $SERVER_NAME.crt
    	key $SERVER_NAME.key
    	auth $HMAC_ALG
    	cipher $CIPHER
    	ncp-ciphers $CIPHER
    	tls-server
    	tls-version-min 1.2
    	tls-cipher $CC_CIPHER
    	#client-config-dir /etc/openvpn/ccd
    	status /var/log/openvpn/status.log
    	verb 3
	management 0.0.0.0 7507" >>/etc/openvpn/server.conf
	
    		# Create client-config-dir dir
    		mkdir -p /etc/openvpn/ccd
    		# Create log dir
    		mkdir -p /var/log/openvpn
    	
    		# Enable routing
    		echo 'net.ipv4.ip_forward=1' >/etc/sysctl.d/99-openvpn.conf
    		if [[ $IPV6_SUPPORT == 'y' ]]; then
    			echo 'net.ipv6.conf.all.forwarding=1' >>/etc/sysctl.d/99-openvpn.conf
    		fi
    		# Apply sysctl rules
    		sysctl --system
    	
    		# If SELinux is enabled and a custom port was selected, we need this
    		if hash sestatus 2>/dev/null; then
    			if sestatus | grep "Current mode" | grep -qs "enforcing"; then
    				if [[ $PORT != '1194' ]]; then
    					semanage port -a -t openvpn_port_t -p "$PROTOCOL" "$PORT"
    				fi
    			fi
    		fi
    	
    		# Finally, restart and enable OpenVPN
    		if [[ $OS == 'arch' || $OS == 'fedora' || $OS == 'centos' || $OS == 'oracle' ]]; then
    			# Don't modify package-provided service
    			cp /usr/lib/systemd/system/openvpn-server@.service /etc/systemd/system/openvpn-server@.service
    	
    			# Workaround to fix OpenVPN service on OpenVZ
    			sed -i 's|LimitNPROC|#LimitNPROC|' /etc/systemd/system/openvpn-server@.service
    			# Another workaround to keep using /etc/openvpn/
    			sed -i 's|/etc/openvpn/server|/etc/openvpn|' /etc/systemd/system/openvpn-server@.service
    			# On fedora, the service hardcodes the ciphers. We want to manage the cipher ourselves, so we remove it from the service
    			if [[ $OS == "fedora" ]]; then
    				sed -i 's|--cipher AES-256-GCM --ncp-ciphers AES-256-GCM:AES-128-GCM:AES-256-CBC:AES-128-CBC:BF-CBC||' /etc/systemd/system/openvpn-server@.service
    			fi
    	
    			systemctl daemon-reload
    			systemctl enable openvpn-server@server
    			systemctl restart openvpn-server@server
    		elif [[ $OS == "ubuntu" ]] && [[ $VERSION_ID == "16.04" ]]; then
    			# On Ubuntu 16.04, we use the package from the OpenVPN repo
    			# This package uses a sysvinit service
    			systemctl enable openvpn
    			systemctl start openvpn
    		else
    			# Don't modify package-provided service
    			cp /lib/systemd/system/openvpn\@.service /etc/systemd/system/openvpn\@.service
    	
    			# Workaround to fix OpenVPN service on OpenVZ
    			sed -i 's|LimitNPROC|#LimitNPROC|' /etc/systemd/system/openvpn\@.service
    			# Another workaround to keep using /etc/openvpn/
    			sed -i 's|/etc/openvpn/server|/etc/openvpn|' /etc/systemd/system/openvpn\@.service
    	
    			systemctl daemon-reload
    			systemctl enable openvpn@server
    			systemctl restart openvpn@server
    		fi
    	
    		if [[ $DNS == 2 ]]; then
    			installUnbound
    		fi
    	
    		# Add iptables rules in two scripts
    		mkdir -p /etc/iptables
    	
    		# Script to add rules
    		echo "#!/bin/sh
    	iptables -t nat -I POSTROUTING 1 -s 10.8.0.0/24 -o $NIC -j MASQUERADE
    	iptables -I INPUT 1 -i tun0 -j ACCEPT
    	iptables -I FORWARD 1 -i $NIC -o tun0 -j ACCEPT
    	iptables -I FORWARD 1 -i tun0 -o $NIC -j ACCEPT
    	iptables -I INPUT 1 -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT" >/etc/iptables/add-openvpn-rules.sh
    	
    		if [[ $IPV6_SUPPORT == 'y' ]]; then
    			echo "ip6tables -t nat -I POSTROUTING 1 -s fd42:42:42:42::/112 -o $NIC -j MASQUERADE
    	ip6tables -I INPUT 1 -i tun0 -j ACCEPT
    	ip6tables -I FORWARD 1 -i $NIC -o tun0 -j ACCEPT
    	ip6tables -I FORWARD 1 -i tun0 -o $NIC -j ACCEPT
    	ip6tables -I INPUT 1 -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT" >>/etc/iptables/add-openvpn-rules.sh
    		fi
    	
    		# Script to remove rules
    		echo "#!/bin/sh
    	iptables -t nat -D POSTROUTING -s 10.8.0.0/24 -o $NIC -j MASQUERADE
    	iptables -D INPUT -i tun0 -j ACCEPT
    	iptables -D FORWARD -i $NIC -o tun0 -j ACCEPT
    	iptables -D FORWARD -i tun0 -o $NIC -j ACCEPT
    	iptables -D INPUT -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT" >/etc/iptables/rm-openvpn-rules.sh
    	
    		if [[ $IPV6_SUPPORT == 'y' ]]; then
    			echo "ip6tables -t nat -D POSTROUTING -s fd42:42:42:42::/112 -o $NIC -j MASQUERADE
    	ip6tables -D INPUT -i tun0 -j ACCEPT
    	ip6tables -D FORWARD -i $NIC -o tun0 -j ACCEPT
    	ip6tables -D FORWARD -i tun0 -o $NIC -j ACCEPT
    	ip6tables -D INPUT -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT" >>/etc/iptables/rm-openvpn-rules.sh
    		fi
    	
    		chmod +x /etc/iptables/add-openvpn-rules.sh
    		chmod +x /etc/iptables/rm-openvpn-rules.sh
    	
    		# Handle the rules via a systemd script
    		echo "[Unit]
    	Description=iptables rules for OpenVPN
    	Before=network-online.target
    	Wants=network-online.target
    	
    	[Service]
    	Type=oneshot
    	ExecStart=/etc/iptables/add-openvpn-rules.sh
    	ExecStop=/etc/iptables/rm-openvpn-rules.sh
    	RemainAfterExit=yes
    	
    	[Install]
    	WantedBy=multi-user.target" >/etc/systemd/system/iptables-openvpn.service
    	
    		# Enable service and apply rules
    		systemctl daemon-reload
    		systemctl enable iptables-openvpn
    		systemctl start iptables-openvpn
    	
    		# If the server is behind a NAT, use the correct IP address for the clients to connect to
    		if [[ $ENDPOINT != "" ]]; then
    			IP=$ENDPOINT
    		fi
    	
    		# client-template.txt is created so we have a template to add further users later
    		echo "client" >/etc/openvpn/client-template.txt
    		if [[ $PROTOCOL == 'udp' ]]; then
    			echo "proto udp" >>/etc/openvpn/client-template.txt
    			echo "explicit-exit-notify" >>/etc/openvpn/client-template.txt
    		elif [[ $PROTOCOL == 'tcp' ]]; then
    			echo "proto tcp-client" >>/etc/openvpn/client-template.txt
    		fi
    		echo "remote $IP $PORT
    	dev tun
    	resolv-retry infinite
    	nobind
    	persist-key
    	persist-tun
    	remote-cert-tls server
    	verify-x509-name $SERVER_NAME name
    	auth $HMAC_ALG
    	auth-nocache
    	cipher $CIPHER
    	tls-client
    	tls-version-min 1.2
    	tls-cipher $CC_CIPHER
    	ignore-unknown-option block-outside-dns
    	setenv opt block-outside-dns # Prevent Windows 10 DNS leak
    	verb 3
	auth-user-pass" >>/etc/openvpn/client-template.txt
    	
    		if [[ $COMPRESSION_ENABLED == "y" ]]; then
    			echo "compress $COMPRESSION_ALG" >>/etc/openvpn/client-template.txt
    		fi
    	
    		# Generate the custom client.ovpn
    		newClient
    		echo "If you want to add more clients, you simply need to run this script another time!"
    	}
    	
    	function newClient() {
    		echo ""
    		echo "Tell me a name for the client."
    		echo "The name must consist of alphanumeric character. It may also include an underscore or a dash."
    	
    		until [[ $CLIENT =~ ^[a-zA-Z0-9_-]+$ ]]; do
    			read -rp "Client name: " -e CLIENT
    		done
    	
    		echo ""
    		echo "Do you want to protect the configuration file with a password?"
    		echo "(e.g. encrypt the private key with a password)"
    		echo "   1) Add a passwordless client"
    		echo "   2) Use a password for the client"
    	
    		until [[ $PASS =~ ^[1-2]$ ]]; do
    			read -rp "Select an option [1-2]: " -e -i 1 PASS
    		done
    	
    		CLIENTEXISTS=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep -c -E "/CN=$CLIENT\$")
    		if [[ $CLIENTEXISTS == '1' ]]; then
    			echo ""
    			echo "The specified client CN was already found in easy-rsa, please choose another name."
    			exit
    		else
    			cd /etc/openvpn/easy-rsa/ || return
    			case $PASS in
    			1)
    				./easyrsa build-client-full "$CLIENT" nopass
    				;;
    			2)
    				echo "⚠️ You will be asked for the client password below ⚠️"
    				./easyrsa build-client-full "$CLIENT"
    				;;
    			esac
    			echo "Client $CLIENT added."
    		fi
    	
    		# Home directory of the user, where the client configuration will be written
    		if [ -e "/home/${CLIENT}" ]; then
    			# if $1 is a user name
    			homeDir="/home/${CLIENT}"
    		elif [ "${SUDO_USER}" ]; then
    			# if not, use SUDO_USER
    			if [ "${SUDO_USER}" == "root" ]; then
    				# If running  as root
    				homeDir="/root"
    			else
    				homeDir="/home/${SUDO_USER}"
    			fi
    		else
    			# if not SUDO_USER, use /root
    			homeDir="/root"
    		fi
    	
    		# Determine if we use tls-auth or tls-crypt
    		if grep -qs "^tls-crypt" /etc/openvpn/server.conf; then
    			TLS_SIG="1"
    		elif grep -qs "^tls-auth" /etc/openvpn/server.conf; then
    			TLS_SIG="2"
    		fi
    	
    		# Generates the custom client.ovpn
    		cp /etc/openvpn/client-template.txt "$homeDir/$CLIENT.ovpn"
    		{
    			echo "<ca>"
    			cat "/etc/openvpn/easy-rsa/pki/ca.crt"
    			echo "</ca>"
    	
    			echo "<cert>"
    			awk '/BEGIN/,/END/' "/etc/openvpn/easy-rsa/pki/issued/$CLIENT.crt"
    			echo "</cert>"
    	
    			echo "<key>"
    			cat "/etc/openvpn/easy-rsa/pki/private/$CLIENT.key"
    			echo "</key>"
    	
    			case $TLS_SIG in
    			1)
    				echo "<tls-crypt>"
    				cat /etc/openvpn/tls-crypt.key
    				echo "</tls-crypt>"
    				;;
    			2)
    				echo "key-direction 1"
    				echo "<tls-auth>"
    				cat /etc/openvpn/tls-auth.key
    				echo "</tls-auth>"
    				;;
    			esac
    		} >>"$homeDir/$CLIENT.ovpn"
    	
    		echo ""
    		echo "The configuration file has been written to $homeDir/$CLIENT.ovpn."
    		echo "Download the .ovpn file and import it in your OpenVPN client."
    	
    		#exit 0
    	}
    	
    	  revokeClient() {
    		NUMBEROFCLIENTS=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep -c "^V")
    		if [[ $NUMBEROFCLIENTS == '0' ]]; then
    			echo ""
    			echo "You have no existing clients!"
    			exit 1
    		fi
    	
    		echo ""
    		echo "Select the existing client certificate you want to revoke"
    		tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') '
    		until [[ $CLIENTNUMBER -ge 1 && $CLIENTNUMBER -le $NUMBEROFCLIENTS ]]; do
    			if [[ $CLIENTNUMBER == '1' ]]; then
    				read -rp "Select one client [1]: " CLIENTNUMBER
    			else
    				read -rp "Select one client [1-$NUMBEROFCLIENTS]: " CLIENTNUMBER
    			fi
    		done
    		CLIENT=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | sed -n "$CLIENTNUMBER"p)
    		cd /etc/openvpn/easy-rsa/ || return
    		./easyrsa --batch revoke "$CLIENT"
    		EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
    		rm -f /etc/openvpn/crl.pem
    		cp /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn/crl.pem
    		chmod 644 /etc/openvpn/crl.pem
    		find /home/ -maxdepth 2 -name "$CLIENT.ovpn" -delete
    		rm -f "/root/$CLIENT.ovpn"
    		sed -i "/^$CLIENT,.*/d" /etc/openvpn/ipp.txt
    	
    		echo ""
    		echo "Certificate for client $CLIENT revoked."
    	}
    	
    	function removeUnbound() {
    		# Remove OpenVPN-related config
    		sed -i '/include: \/etc\/unbound\/openvpn.conf/d' /etc/unbound/unbound.conf
    		rm /etc/unbound/openvpn.conf
    	
    		until [[ $REMOVE_UNBOUND =~ (y|n) ]]; do
    			echo ""
    			echo "If you were already using Unbound before installing OpenVPN, I removed the configuration related to OpenVPN."
    			read -rp "Do you want to completely remove Unbound? [y/n]: " -e REMOVE_UNBOUND
    		done
    	
    		if [[ $REMOVE_UNBOUND == 'y' ]]; then
    			# Stop Unbound
    			systemctl stop unbound
    	
    			if [[ $OS =~ (debian|ubuntu) ]]; then
    				apt-get remove --purge -y unbound
    			elif [[ $OS == 'arch' ]]; then
    				pacman --noconfirm -R unbound
    			elif [[ $OS =~ (centos|amzn|oracle) ]]; then
    				yum remove -y unbound
    			elif [[ $OS == 'fedora' ]]; then
    				dnf remove -y unbound
    			fi
    	
    			rm -rf /etc/unbound/
    	
    			echo ""
    			echo "Unbound removed!"
    		else
    			systemctl restart unbound
    			echo ""
    			echo "Unbound wasn't removed."
    		fi
    	}
    	
    	function removeOpenVPN() {
    		echo ""
    		read -rp "Do you really want to remove OpenVPN? [y/n]: " -e -i n REMOVE
    		if [[ $REMOVE == 'y' ]]; then
    			# Get OpenVPN port from the configuration
    			PORT=$(grep '^port ' /etc/openvpn/server.conf | cut -d " " -f 2)
    			PROTOCOL=$(grep '^proto ' /etc/openvpn/server.conf | cut -d " " -f 2)
    	
    			# Stop OpenVPN
    			if [[ $OS =~ (fedora|arch|centos|oracle) ]]; then
    				systemctl disable openvpn-server@server
    				systemctl stop openvpn-server@server
    				# Remove customised service
    				rm /etc/systemd/system/openvpn-server@.service
    			elif [[ $OS == "ubuntu" ]] && [[ $VERSION_ID == "16.04" ]]; then
    				systemctl disable openvpn
    				systemctl stop openvpn
    			else
    				systemctl disable openvpn@server
    				systemctl stop openvpn@server
    				# Remove customised service
    				rm /etc/systemd/system/openvpn\@.service
    			fi
    	
    			# Remove the iptables rules related to the script
    			systemctl stop iptables-openvpn
    			# Cleanup
    			systemctl disable iptables-openvpn
    			rm /etc/systemd/system/iptables-openvpn.service
    			systemctl daemon-reload
    			rm /etc/iptables/add-openvpn-rules.sh
    			rm /etc/iptables/rm-openvpn-rules.sh
    	
    			# SELinux
    			if hash sestatus 2>/dev/null; then
    				if sestatus | grep "Current mode" | grep -qs "enforcing"; then
    					if [[ $PORT != '1194' ]]; then
    						semanage port -d -t openvpn_port_t -p "$PROTOCOL" "$PORT"
    					fi
    				fi
    			fi
    	
    			if [[ $OS =~ (debian|ubuntu) ]]; then
    				apt-get remove --purge -y openvpn
    				if [[ -e /etc/apt/sources.list.d/openvpn.list ]]; then
    					rm /etc/apt/sources.list.d/openvpn.list
    					apt-get update
    				fi
    			elif [[ $OS == 'arch' ]]; then
    				pacman --noconfirm -R openvpn
    			elif [[ $OS =~ (centos|amzn|oracle) ]]; then
    				yum remove -y openvpn
    			elif [[ $OS == 'fedora' ]]; then
    				dnf remove -y openvpn
    			fi
    	
    			# Cleanup
    			find /home/ -maxdepth 2 -name "*.ovpn" -delete
    			find /root/ -maxdepth 1 -name "*.ovpn" -delete
    			rm -rf /etc/openvpn
    			rm -rf /usr/share/doc/openvpn*
    			rm -f /etc/sysctl.d/99-openvpn.conf
    			rm -rf /var/log/openvpn
    	
    			# Unbound
    			if [[ -e /etc/unbound/openvpn.conf ]]; then
    				removeUnbound
    			fi
    			echo ""
    			echo "OpenVPN removed!"
    		else
    			echo ""
    			echo "Removal aborted!"
    		fi
    	}
    	
    	function manageMenu() {
    		echo "Welcome to OpenVPN-install!"
    		echo "The git repository is available at: https://github.com/angristan/openvpn-install"
    		echo ""
    		echo "It looks like OpenVPN is already installed."
    		echo ""
    		echo "What do you want to do?"
    		echo "   1) Add a new user"
    		echo "   2) Revoke existing user"
    		echo "   3) Remove OpenVPN"
    		echo "   4) Exit"
    		until [[ $MENU_OPTION =~ ^[1-4]$ ]]; do
    			read -rp "Select an option [1-4]: " MENU_OPTION
    		done
    	
    		case $MENU_OPTION in
    		1)
    			newClient
    			;;
    		2)
    			revokeClient
    			;;
    		3)
    			removeOpenVPN
    			;;
    		4)
    			exit 0
    			;;
    		esac
    	}
    	
    	# Check for root, TUN, OS...
    	# Check for root, TUN, OS...
    	initialCheck
    	
    	# Check if OpenVPN is already installed
    	if [[ -e /etc/openvpn/server.conf && $AUTO_INSTALL != "y" ]]; then
    		manageMenu
    	else
    		installOpenVPN
    	fi
    	radiusConfig
	systemctl restart openvpn
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
			echo "VENDOR          Microsoft       311     Microsoft
			BEGIN VENDOR    Microsoft
			ATTRIBUTE       MS-CHAP-Response        1       string  Microsoft
			ATTRIBUTE       MS-CHAP-Error           2       string  Microsoft
			ATTRIBUTE       MS-CHAP-CPW-1           3       string  Microsoft
			ATTRIBUTE       MS-CHAP-CPW-2           4       string  Microsoft
			ATTRIBUTE       MS-CHAP-LM-Enc-PW       5       string  Microsoft
			ATTRIBUTE       MS-CHAP-NT-Enc-PW       6       string  Microsoft
			ATTRIBUTE       MS-MPPE-Encryption-Policy 7     string  Microsoft
			ATTRIBUTE       MS-MPPE-Encryption-Type 8       string  Microsoft
			ATTRIBUTE       MS-MPPE-Encryption-Types  8     string  Microsoft
			ATTRIBUTE       MS-RAS-Vendor           9       integer Microsoft
			ATTRIBUTE       MS-CHAP-Domain          10      string  Microsoft
			ATTRIBUTE       MS-CHAP-Challenge       11      string  Microsoft
			ATTRIBUTE       MS-CHAP-MPPE-Keys       12      string  Microsoft encrypt=1
			ATTRIBUTE       MS-BAP-Usage            13      integer Microsoft
			ATTRIBUTE       MS-Link-Utilization-Threshold 14 integer        Microsoft
			ATTRIBUTE       MS-Link-Drop-Time-Limit 15      integer Microsoft
			ATTRIBUTE       MS-MPPE-Send-Key        16      string  Microsoft
			ATTRIBUTE       MS-MPPE-Recv-Key        17      string  Microsoft
			ATTRIBUTE       MS-RAS-Version          18      string  Microsoft
			ATTRIBUTE       MS-Old-ARAP-Password    19      string  Microsoft
			ATTRIBUTE       MS-New-ARAP-Password    20      string  Microsoft
			ATTRIBUTE       MS-ARAP-PW-Change-Reason 21     integer Microsoft
			ATTRIBUTE       MS-Filter               22      string  Microsoft
			ATTRIBUTE       MS-Acct-Auth-Type       23      integer Microsoft
			ATTRIBUTE       MS-Acct-EAP-Type        24      integer Microsoft
			ATTRIBUTE       MS-CHAP2-Response       25      string  Microsoft
			ATTRIBUTE       MS-CHAP2-Success        26      string  Microsoft
			ATTRIBUTE       MS-CHAP2-CPW            27      string  Microsoft
			ATTRIBUTE       MS-Primary-DNS-Server   28      ipaddr
			ATTRIBUTE       MS-Secondary-DNS-Server 29      ipaddr
			ATTRIBUTE       MS-Primary-NBNS-Server  30      ipaddr Microsoft
			ATTRIBUTE       MS-Secondary-NBNS-Server 31     ipaddr Microsoft
			VALUE           MS-BAP-Usage            Not-Allowed     0
			VALUE           MS-BAP-Usage            Allowed         1
			VALUE           MS-BAP-Usage            Required        2
			VALUE   MS-ARAP-PW-Change-Reason        Just-Change-Password            1
			VALUE   MS-ARAP-PW-Change-Reason        Expired-Password                2
			VALUE   MS-ARAP-PW-Change-Reason        Admin-Requires-Password-Change  3
			VALUE   MS-ARAP-PW-Change-Reason        Password-Too-Short              4
			VALUE           MS-Acct-Auth-Type       PAP             1
			VALUE           MS-Acct-Auth-Type       CHAP            2
			VALUE           MS-Acct-Auth-Type       MS-CHAP-1       3
			VALUE           MS-Acct-Auth-Type       MS-CHAP-2       4
			VALUE           MS-Acct-Auth-Type       EAP             5
			VALUE           MS-Acct-EAP-Type        MD5             4
			VALUE           MS-Acct-EAP-Type        OTP             5
			VALUE           MS-Acct-EAP-Type        Generic-Token-Card      6
			VALUE           MS-Acct-EAP-Type        TLS             13" >> /etc/radiusclient/dictionary.microsoft
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
			sed -i '/.*net.ipv4.ip.*/s/^#//g' /etc/sysctl.conf
			sysctl -p
			echo "
			duplicate-cn
			management 0.0.0.0 7506
			plugin /usr/lib/openvpn/radiusplugin.so  /usr/lib/openvpn/radiusplugin.cnf
			log /var/log/openvpn/pa-ibs.log
			status /var/log/openvpn/status-pa-ibs.log" >> /etc/openvpn/server.conf
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
	OpenVPNConfig=/etc/openvpn/server.conf
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
 function edit(){
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
	OpenVPNConfig=/etc/openvpn/server.conf
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
function installocs(){
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
NIC=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
iptables -t nat -A POSTROUTING -s 10.69.2.0/24 -o $NIC -j MASQUERADE
touch /etc/iptable-rules.sh
chmod +x /etc/iptables/iptable-rules.sh
echo -e "iptables -t nat -I POSTROUTING -s 10.69.2.0/24 -o $NIC -j MASQUERADE" |  tee -a /etc/iptables/iptable-rules.sh
systemctl restart ocserv
radiusConfig
systemctl restart ocserv
}
function installl2tp(){
#!/bin/bash
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
  check_ip "$public_ip" || public_ip=$(dig @resolver1.opendns.com -t A -4 myip.opendns.com +short)
  check_ip "$public_ip" || public_ip=$(wget -t 3 -T 15 -qO- http://ipv4.icanhazip.com)
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
NIC=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
iptables -t nat -A POSTROUTING -s 10.69.3.0/24 -o $NIC -j MASQUERADE
touch /etc/iptable-rules.sh
chmod +x /etc/iptables/iptable-rules.sh
echo -e "iptables -t nat -I POSTROUTING -s 10.69.3.0/24 -o $NIC -j MASQUERADE" |  tee -a /etc/iptables/iptable-rules.sh
radiusConfig
systemctl restart xl2tpd
}
function installpptp(){
echo "Installing..."
apt update -qq ; apt install pptpd build-essential libgcrypt20-dev -y
#echo -e "localip 192.168.120.1\nremoteip 192.168.120.10-250" |  tee -a /etc/pptpd.conf
echo -e "ms-dns 8.8.8.8\nms-dns 9.9.9.9\nplugin /usr/lib/pppd/2.4.7/radius.so\nplugin /usr/lib/pppd/2.4.7/radattr.so" |  tee -a /etc/ppp/pptpd-options
echo 'net.ipv4.ip_forward=1' >/etc/sysctl.d/99-openvpn.conf
sysctl --system
NIC=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
iptables -t nat -A POSTROUTING -s 10.69.4.0/24 -o $NIC -j MASQUERADE
touch /etc/iptable-rules.sh
chmod +x /etc/iptables/iptable-rules.sh
echo -e "iptables -t nat -I POSTROUTING -s 10.69.4.0/24 -o $NIC -j MASQUERADE" |  tee -a /etc/iptables/iptable-rules.sh
systemctl enable pptpd
systemctl start pptpd
radiusConfig
systemctl restart pptpd
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
	echo "  
	 ####    ####   #    #  ######  #####   #    #  ######   #####
	#    #  #    #  #    #  #       #    #  ##   #  #          #
	#       #    #  #    #  #####   #    #  # #  #  #####      #
	#       #    #  #    #  #       #####   #  # #  #          #
	#    #  #    #   #  #   #       #   #   #   ##  #          #
	 ####    ####     ##    ######  #    #  #    #  ######     #"
	echo
	echo
	echo "1) Install OpenVPN Server With IBSng Config"
	echo "2) Install Cisco Any Connect Server With IBSng Config"
	echo "3) Install L2TP Server With IBSng Config"
	echo "4) Install PPTP Server With IBSng Config"
	echo "5) Install IKEv2 Server With IBSng Config"
	echo "6) Install Socksv5 Server With IBSng Config"
	echo "7) Edit IBSng Configuration"
	echo
	echo "0) Exit"
	echo
	read -rp "Select a number:" Selection

	if [ $Selection -gt 7 ]
	then
		echo "The variable is greater than 7."
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
		installikev2
	elif [ $Selection -eq 6 ]
	then
		installsocks5
	elif [ $Selection -eq 7 ]
	then
		edit
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
