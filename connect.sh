#!/bin/bash
clear
set +H

# Set Defaults
BACKTITLE="sbox Setup"
VPNIP="174.63.244.248"
EXTIF=""
INTIF=""
SSID=""
KEY=""
PW=""
QUIET=0
# [TODO] Build a description header
# usage() { echo "Usage: $0 -e <wlan\*|eth0> -i <wlan\*|eth0> -s <SSID> -k <KEY> -q" 1>&2; exit 1; }

# Parse arguments
while getopts qe:i:s:k: option
do
	case ${option}
	in
		e) EXTIF=$OPTARG;;	# external interface (i.e., wlan0, eth0, etc.)
		i) INTIF=$OPTARG;;	# internal interface (i.e., wlan0, eth0, etc.)
		s) SSID=$OPTARG;;	# WIFI SSID
		k) KEY=$OPTARG;;	# WIFI Key (if encrypted)
		q) QUIET=1;;		# Disables connectivity checks
		p) PW=$OPTARG;;		# VPN Password
		:) echo "$OPTARG requires an argument."	# If expected argument omitted.
		usage;;
		*) usage;; 						# If no options are matched.
	esac
done

# Close any existing OPENVPN connections
RESPONSE=ps -a | grep openvpn
if [ $RESPONSE == 0 ]; then
	sudo pkill -SIGTERM -f 'openvpn'
	echo "Waiting 5 seconds for existing VPN to terminate..."
	sleep 5
	clear
fi

# List the available interfaces and ask the user to choose the internal (private) and external (public) interfaces
if [ $EXTIF == "" ]; then
	TITLE="Step 1 of 4: Interface Setup"
	VALUE=" " 
	for i in $(ls /sys/class/net | grep -vi "lo"); do ((item++)); VALUE="$VALUE ${i} up" ; done
	EXTIF=$(whiptail --backtitle "$BACKTITLE" --title "$TITLE" --menu "Select the external network interface.\\n\\n*** NOTE: This is usually a WLAN interface. ***" 20 60 10 ${VALUE} 3>&1 1>&2 2>&3)
	RESPONSE=$?
	if [ $RESPONSE != 0 ]; then
       		whiptail --backtitle "$BACKTITLE" --title "$TITLE" --msgbox "User CANCELLED." 12 80
	        exit 1
	fi
fi

if [ $INTIF == "" ]; then
	VALUE=" " 
	for i in $(ls /sys/class/net | grep -viE "lo|$EXTIF"); do ((item++)); VALUE="$VALUE ${i}" ; done
	INTIF=$(whiptail --backtitle "$BACKTITLE" --title "$TITLE" --menu "Select the internal network interface.\\n\\n*** NOTE: This is usually an ETH interface. ***" 20 60 10 ${VALUE} 3>&1 1>&2 2>&3)
	RESPONSE=$?
	if [ $RESPONSE != 0 ]; then
        	whiptail --backtitle "$BACKTITLE" --title "$TITLE" --msgbox "User CANCELLED." 12 80
	        exit 1
	fi
fi

if [ $QUIET == 0 ]; then 
	if ! (whiptail --backtitle "$BACKTITLE" --title "$TITLE" --yesno "Interface selection complete.\\n*** NOTE: Incorrect configuration could result in a DOS condition! ***\\nIf DOS occurs, unplug, reboot, and try again.\\n\\nExternal:   $EXTIF\\nInternal:   $INTIF\\n\\nRotating MAC address and configuring firewall..." 20 78) then
		whiptail --backtitle "$BACKTITLE" --title "$TITLE" --msgbox "User CANCELLED." 12 80
	        exit 1
	fi
fi

# [TODO] cycle the MAC address on the external interface
# sudo ifconfig $EXTIF down
# sudo service networking stop
# sudo macchanger -A $EXTIF		# Troubleshooting; wlan1 becomes non-responsive when using macchanger
# sudo service networking start
# sudo ifconfig $EXTIF up

# Configure the firewall rules
echo "Resetting IPTABLES..."
sudo iptables -P INPUT ACCEPT
sudo iptables -F

echo "Building logging interfaces..."
sudo iptables -N LOGGING-DRP
sudo iptables -A LOGGING-DRP -j LOG -m limit --limit 5/s --log-prefix "IPTables-Dropped: " --log-level 4
sudo iptables -A LOGGING-DRP -j DROP

sudo iptables -N LOGGING-ACP
sudo iptables -A LOGGING-ACP -j LOG -m limit --limit 5/s --log-prefix "IPTables-Accepted: " --log-level 4
sudo iptables -A LOGGING-ACP -j ACCEPT

echo "Configuring VPN INPUT Chain..."
sudo iptables -A INPUT -i lo -j ACCEPT
sudo iptables -A INPUT -i eth0 -p tcp --dport ssh -j ACCEPT
sudo iptables -A INPUT -i $EXTIF -s $VPNIP -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo iptables -A INPUT -i $EXTIF -p udp --sport 53 -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo iptables -A INPUT -i $EXTIF -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo iptables -A INPUT -i $EXTIF -m pkttype --pkt-type broadcast -j DROP
sudo iptables -A INPUT -i $EXTIF -m iprange --dst-range 224.0.0.0-239.255.255.255 -j DROP
sudo iptables -A INPUT -i $EXTIF -d 255.255.255.255 -j DROP
sudo iptables -A INPUT -i $EXTIF -s 0.0.0.0 -j DROP
sudo iptables -A INPUT -i $INTIF -p udp --dport 53 -j ACCEPT
sudo iptables -A INPUT -i $INTIF -j ACCEPT
sudo iptables -A INPUT -i tun0 -j ACCEPT
sudo iptables -A INPUT -j LOGGING-ACP
sudo iptables -P INPUT DROP

echo "Configuring FORWARD Chain..."
sudo iptables -t nat -A POSTROUTING -o tun0 -j MASQUERADE

sudo iptables -A FORWARD -i tun0 -o $INTIF -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo iptables -A FORWARD -i $INTIF -o tun0 -j ACCEPT
sudo iptables -A FORWARD -j LOGGING-DRP
sudo iptables -P FORWARD DROP

echo "Configuring OUTPUT Chain..."
sudo iptables -A OUTPUT -o $EXTIF -d $VPNIP -p tcp --dport 443 -j ACCEPT
sudo iptables -A OUTPUT -o $EXTIF -d $VPNIP -p udp --dport 1194 -j ACCEPT
sudo iptables -A OUTPUT -o $EXTIF -p tcp --dport 80 -j ACCEPT
sudo iptables -A OUTPUT -o $EXTIF -p tcp --dport 443 -j ACCEPT
sudo iptables -A OUTPUT -o $EXTIF -p udp --dport 53 -j ACCEPT

sudo iptables -A OUTPUT -o $INTIF -j ACCEPT
sudo iptables -A OUTPUT -o tun0 -j ACCEPT
sudo iptables -A OUTPUT -j LOGGING-ACP
sudo iptables -P OUTPUT DROP

echo "Done Configuring IPTables (waiting 5 seconds for interfaces)..."
sleep 5

# If the external interface is WIFI (i.e., WLANx), join the WLAN
if [[ $EXTIF == wlan* ]]; then
TITLE="Step 2 of 4: Join External Interface to Public Network"
	if [ $SSID == "" ]; then
		echo ""
		echo "Scanning for SSID..."

		## scan for SSID and select
		VALUE=$(sudo iwlist $EXTIF scan | egrep "Encryption|ESSID" | sed -e "s/\"\"/<hidden>/" -e "s/ \{1,\}//" -e "s/ESSID://" -e "s/Encryption key://" -e "s/\"//g" | awk '{ORS = (NR % 2 == 0)? "\n" : " "; print}' | awk '{s=$1;$1=$NF;$NF=s}1' | sort)

		# echo "Parsing SSIDs..."
		# echo "($VALUE)"

		SSID=$(whiptail --backtitle "$BACKTITLE" --title "$TITLE" --menu "Select the External WIFI Network." 20 60 10 $VALUE 3>&1 1>&2 2>&3)
		exitstatus=$?

		# echo "Exit Status was....$exitstatus"
		# echo "Processing Choices..."
		# echo "($SSID)"

		if [ $exitstatus -eq 255 ]; then 
	        	SSID=$(whiptail --backtitle "$BACKTITLE" --title "$TITLE" --inputbox "There was a problem with the choices. Enter the SSID manually." 8 78 $DEFSSID 3>&1 1>&2 2>&3)
			exitstatus=$?
		fi

		if [ $exitstatus -eq 0 ]; then	# 0 = OK / 1 = CANCEL

			# determine if the SSID needs to be manually entered.
			if [ "$SSID" == "<hidden>" ]; then
				echo "Enter hidden network"
        			SSID=$(whiptail --backtitle "$BACKTITLE" --title "$TITLE" --inputbox "Manually enter the hidden network SSID" 8 78 3>&1 1>&2 2>&3)
			fi
		else
			whiptail --backtitle "$BACKTITLE" --title "$TITLE" --msgbox "Network SSID selection was cancelled. Setup cannot continue." 12 80
			exit 1
		fi
	fi

	# determine whether a key is required
	CRYPTO=$(sudo iwlist $EXTIF scan | egrep "Encryption|ESSID" | sed -e "s/ \{1,\}//" -e "s/ESSID://" -e "s/Encryption key://" -e "s/\"//g" | awk '{ORS = (NR % 2 == 0)? "\n" : " "; print}' | awk '{s=$1;$1=$NF;$NF=s}1' | grep $SSID | grep -c on)

	if [ $CRYPTO != 0 ]; then
		if [ $KEY == "" ]; then
			KEY=$(whiptail --backtitle "$BACKTITLE" --title "$TITLE" --inputbox "Enter the network KEY?" 8 78 3>&1 1>&2 2>&3)
			exitstatus=$?
			
			if [ $exitstatus != 0 ]; then
				whiptail --backtitle "$BACKTITLE" --title "$TITLE" --msgbox "User cancelled network KEY." 12 80
				exit 1
			fi
		fi
		# configure the interface
		wpa_passphrase $SSID $KEY > net.cfg
		sudo wpa_supplicant -i$EXTIF -cnet.cfg -B
		rm -f net.cfg
	else
		sudo iwconfig $EXTIF essid $SSID
	fi
fi

# wait for the interface to grab an IP Address
for ((i = 0 ; i <= 100 ; i+=5)); do
	sleep 1
	if ifconfig $EXTIF | grep 'inet' > /dev/null; then 
		break
	fi
	echo $i
done | whiptail --title "$TITLE" --gauge "Waiting (up to 20 seconds) for $SSID on $EXTIF..." 8 85 0

if [ $i = 100 ]; then
	if [ $QUIET == 0 ]; then 
		whiptail --backtitle "$BACKTITLE" --title "$TITLE" --msgbox "$EXTIF is not available. Check the connectivity and try again.\n-The network may be non-responsive.\n-The network KEY may be incorrect." 12 80
		exit 1
	else 
		echo "$EXTIF is not available. Check the connectivity and try again (the network may be non-responsive, or the network KEY may be incorrect)."
		exit 1
	fi
	
else
	if [ $QUIET == 0 ]; then 
		# open www.google.com to verify connectivity and sign in to the captive portal (if necessary)
		INET=$(ifconfig $EXTIF | grep 'inet')
		exitstatus=$?

		if [ $exitstatus -eq 0 ]; then
			whiptail --backtitle "$BACKTITLE" --title "$TITLE" --msgbox "Connection successful.\\n$INET\\nELINKS will open and attempt to browse to GOOGLE.\\nA captive portal may require authentication.\\nWhen complete, press 'q' to exit ELINKS and resume the configuration.\\nIf the connection times out, you will get a change to exit the configuration." 15 90
			elinks www.google.com

		        if ! (whiptail --backtitle "$BACKTITLE" --title "$TITLE" --yesno "Was the Internet available?" 20 78) then
		                whiptail --backtitle "$BACKTITLE" --title "$TITLE" --msgbox "The Internet is not available. Check connectivity and try again." 12 80
	                	exit 1
        		fi
		else
			whiptail --backtitle "$BACKTITLE" --title "$TITLE" --msgbox "$EXTIF is not available. Check connectivity and try again." 12 80
			exit 1
		fi
	fi
fi
	
# ask for the VPN password
TITLE="Step 3 of 4: Establish the VPN Tunnel"
if [ $EXTIF == "" ]; then
	PW=$(whiptail --backtitle "$BACKTITLE" --title "$TITLE" --inputbox "Enter the VPN certificate password." 8 78 greatpain 3>&1 1>&2 2>&3)
	exitstatus=$?
	
	if [ $exitstatus != 0 ]; then
		whiptail --backtitle "$BACKTITLE" --title "$TITLE" --msgbox "User cancelled the VPN Certificate password." 12 80
		exit 1
	fi
fi
   
# start the VPN Tunnel
clear
# perform a port test. If successful
echo "Starting the VPN Tunnel (UDP 1194)"

# [TODO] how to pass the certificate password to openvpn
# sudo echo $PW > auth.txt
sudo openvpn --config /etc/openvpn/client/remote-udp1194.ovpn --auth-nocache --askpass /etc/openvpn/client/auth.txt &
# sudo openvpn --config  /etc/openvpn/client/remote-udp1194.ovpn &
# sudo rm auth.txt

# [TODO] Switch to TCP option if UDP fails.
# clear
# echo "Starting the VPN Tunnel (TCP 443)"
# [TODO] how to pass the certificate password to openvpn
# sudo echo $PW > auth.txt
# sudo openvpn --config /etc/openvpn/client/remote-tcp443.ovpn --askpass  /etc/openvpn/client/auth.txt &
# sudo openvpn --config /etc/openvpn/client/remote-tcp443.ovpn &
# sudo rm auth.txt

# [TODO] Handle an error in which neither connection succeeds.
# echo "Launching password agent..."
# sudo systemd-tty-ask-password-agent

echo "Clearing DNS configurations from external interface..."
sudo resolvconf -d $EXTIF.dhcp

echo "Waiting 10 seconds for VPN)..."
sleep 10

echo "Done Configuring Interfaces!"


# Establish WLAN if the internal interface is WIFI (i.e., WLANx)
for i in $(ls /sys/class/net | grep -viE "lo|$EXTIF|$INTIF"); do ((item++)); VALUE="${i}" ; done

# if [ ${#VALUE[@]} > 0]; then		# If there is an open WIFI interface
#	if [[ $VALUE == wlan* ]] ; then
#		echo "WLAN"
#	fi

#	if [ $QUIET == 0 ]; then	#
#		
#	fi
#
# 	./apconfig.sh -i $VALUE 
# fi

## Provide a summary screen
# internal interface, IP, mask, gw
# external interface, IP, mask, gw
# tunnel interface, IP, mask, gw
# internal WIFI SSID and key (if appropriate)

# MENU CHOICES
# deploy Honey Pots
# drop to shell
# reboot

# Deploy the Honey Pots
TITLE="OPTIONAL: Deploy Honey Pots"
