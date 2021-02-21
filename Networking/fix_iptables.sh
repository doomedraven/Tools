#!/bin/bash
# Fix when docker breaks your iptables
if [ $# -eq 0 ] || [ $# -lt 2 ]; then
    echo "$0 <netowrk range> <vir_iface> <real_iface>"
    echo "    example: $0 192.168.1.0 virbr0 eno0"
    exit 1
fi

echo "[+] Setting iptables"
iptables -t nat -A POSTROUTING -o "$2" -j MASQUERADE
iptables -A FORWARD -i "$2" -o "$2" -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -i "$2" -o "$2" -j ACCEPT
iptables -I FORWARD -m physdev --physdev-is-bridged -j ACCEPT
iptables -I FORWARD -o "$2" -d  "$1"/24 -j ACCEPT
iptables -t nat -A POSTROUTING -s "$1"/24 -j MASQUERADE
iptables -A FORWARD -o "$2" -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -i "$2" -o "$3" -j ACCEPT
iptables -A FORWARD -i "$2" -o lo -j ACCEPT

echo "[+] Setting network options"
# https://forums.fedoraforum.org/showthread.php?312824-Bridge-broken-after-docker-install&s=ffc1c60cccc19e46c01b9a8e0fcd0c35&p=1804899#post1804899
{
    echo "net.bridge.bridge-nf-call-ip6tables=0";
    echo "net.bridge.bridge-nf-call-iptables=0";
    echo "net.bridge.bridge-nf-call-arptables=0";
    echo "net.ipv4.conf.all.forwarding=1";
    echo "net.ipv4.ip_forward=1";
} >> /etc/sysctl.conf
sysctl -p
echo "iptables -A FORWARD -i $2 -o $2 -j ACCEPT" >> /etc/network/if-pre-up.d/kvm_bridge_iptables

virsh nwfilter-list
