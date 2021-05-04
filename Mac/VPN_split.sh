#!/bin/bash
# replace "yourcomapy.com." with your real root domain
# replace "VPN_IP" with real VPN public ip
# replace dns1 and dns2 with your real dns
# To get real dns, add --dump --verbose to vpn-slice when starts with openconnect

function _check_brew() {
    if [ ! -f /usr/local/bin/brew ]; then
        /usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
    fi
}


_check_brew
brew install openconnect git unbound
pip3 install git+https://github.com/dlenski/vpn-slice.git


# how to configure local dns server
# https://calomel.org/unbound_dns.html 
# https://sizeof.cat/post/unbound-on-macos/
# https://nlnetlabs.nl/documentation/unbound/unbound.conf/
#(curl --silent https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn-social/hosts | grep '^0\.0\.0\.0' | sort) | awk '{print "local-zone: \""$2"\" refuse"}' > /usr/local/etc/unbound/zone-block-general.conf
sudo dscl . -create /Groups/_unbound
sudo dscl . -create /Groups/_unbound PrimaryGroupID 444
sudo dscl . -create /Users/_unbound
sudo dscl . -create /Users/_unbound RecordName _unbound unbound
sudo dscl . -create /Users/_unbound RealName "Unbound DNS server"
sudo dscl . -create /Users/_unbound UniqueID 444
sudo dscl . -create /Users/_unbound PrimaryGroupID 444
sudo dscl . -create /Users/_unbound UserShell /usr/bin/false
sudo dscl . -create /Users/_unbound Password '*'
sudo dscl . -create /Groups/_unbound GroupMembership _unbound

sudo /usr/local/opt/unbound/sbin/unbound-anchor -a /usr/local/etc/unbound/root.key
sudo /usr/local/opt/unbound/sbin/unbound-control-setup -d /usr/local/etc/unbound
sudo cp /usr/local/etc/unbound/unbound.conf /usr/local/etc/unbound/unbound.conf_original
sudo curl --silent -o /usr/local/etc/unbound/root.hints https://www.internic.net/domain/named.cache

cat >> /usr/local/etc/unbound/unbound.conf << EOL
server:
    # log verbosity
    verbosity: 3
    # domain-insecure: *
    # logfile: "/tmp/unbound.log"
    # log-queries: yes
    # log-time-ascii: yes
    interface: 127.0.0.1
    access-control: 127.0.0.1/8 allow
    chroot: ""
    username: "_unbound"
    # auto-trust-anchor-file: "/usr/local/etc/unbound/root.key"
    # answer DNS queries on this port
    port: 53
    # enable IPV4
    do-ip4: yes
    # disable IPV6
    do-ip6: no
    # enable UDP
    do-udp: yes
    # enable TCP, you could disable this if not needed, UDP is quicker
    do-tcp: yes
    # which client IPs are allowed to make (recursive) queries to this server
    access-control: 10.0.0.0/8 allow
    access-control: 127.0.0.0/8 allow
    access-control: 192.168.0.0/16 allow
    root-hints: "/usr/local/etc/unbound/root.hints"
    # do not answer id.server and hostname.bind queries
    hide-identity: yes
    # do not answer version.server and version.bind queries
    hide-version: yes
    # will trust glue only if it is within the servers authority
    harden-glue: yes
    # require DNSSEC data for trust-anchored zones, if such data
    # is absent, the zone becomes  bogus
    harden-dnssec-stripped: yes
    # use 0x20-encoded random bits in the query to foil spoof attempts
    use-caps-for-id: yes
    # the time to live (TTL) value lower bound, in seconds
    cache-min-ttl: 3600
    # the time to live (TTL) value cap for RRsets and messages in the cache
    cache-max-ttl: 86400
    # perform prefetching of close to expired message cache entries
    prefetch: yes
    num-threads: 4
    msg-cache-slabs: 8
    rrset-cache-slabs: 8
    infra-cache-slabs: 8
    key-cache-slabs: 8
    rrset-cache-size: 256m
    msg-cache-size: 128m
    so-rcvbuf: 1m
    private-address: 192.168.0.0/16
    private-address: 172.16.0.0/12
    private-address: 10.0.0.0/8
    private-domain: "home.lan"
    unwanted-reply-threshold: 10000
    val-clean-additional: yes
    # additional blocklist (Steven Black hosts file, read above)
    # include: /usr/local/etc/unbound/zone-block-general.conf
    private-domain: "yourcomapy.com."
    local-data: "vpn.yourcomapy.com.  IN A VPN_IP"
remote-control:
    control-enable: yes
    control-interface: 127.0.0.1
    server-key-file: "/usr/local/etc/unbound/unbound_server.key"
    server-cert-file: "/usr/local/etc/unbound/unbound_server.pem"
    control-key-file: "/usr/local/etc/unbound/unbound_control.key"
    control-cert-file: "/usr/local/etc/unbound/unbound_control.pem"

forward-zone:
   name: "yourcomapy.com."
   #forward-ssl-upstream:yes
   forward-addr: dns1
   forward-addr: dns2

forward-zone:
   name: "."
   # forward-ssl-upstream: yes
   forward-addr: 1.1.1.1@53#one.one.one.one
   forward-addr: 8.8.8.8@53#dns.google
   forward-addr: 9.9.9.9@53#dns.quad9.net
   forward-addr: 1.0.0.1@53#one.one.one.one
   forward-addr: 8.8.4.4@53#dns.google
   forward-addr: 149.112.112.112@53#dns.quad9.net
EOL

sudo chown -R _unbound:staff /usr/local/etc/unbound
sudo chmod 640 /usr/local/etc/unbound/*

sudo brew services start unbound

networksetup -setdnsservers Wi-Fi 127.0.0.1
networksetup -getdnsservers Wi-Fi

