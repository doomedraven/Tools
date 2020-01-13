#!/bin/bash
# By @doomedraven - https://twitter.com/D00m3dR4v3n

# Copyright (C) 2011-2019 DoomedRaven.
# This file is part of Tools - https://github.com/doomedraven/Tools
# See the file 'LICENSE.md' for copying permission.

# Huge thanks to: @NaxoneZ @kevoreilly @ENZOK


# Static values
# Where to place everything
NETWORK_IFACE=virbr1
# for tor
IFACE_IP="192.168.1.1"
# DB password
PASSWD="SuperPuperSecret"
DIST_MASTER_IP=X.X.X.X

function issues() {
cat << EOI
Problems with PyOpenSSL?
    sudo rm -rf /usr/local/lib/python2.7/dist-packages/OpenSSL/
    sudo rm -rf /home/cuckoo/.local/lib/python2.7/site-packages/OpenSSL/
    sudo apt install --reinstall python-openssl

Problem with PIP?
    sudo python -m pip uninstall pip && sudo apt install python-pip --reinstall

Problem with pillow:
    * ValueError: jpeg is required unless explicitly disabled using --disable-jpeg, aborting
    * ValueError: zlib is required unless explicitly disabled using --disable-zlib, aborting
Solution:
    # https://askubuntu.com/a/1094768
    # you may need to adjust version of libjpeg-turbo8
    sudo apt install zlib1g-dev libjpeg-turbo8-dev libjpeg-turbo8=1.5.2-0ubuntu5
EOI
}

function usage() {
cat << EndOfHelp
    You need to edit NETWORK_IFACE, IFACE_IP and PASSWD for correct install

    Usage: $0 <command> <cuckoo_version> <iface_ip> | tee $0.log
        Example: $0 all cape 192.168.1.1 | tee $0.log
    Commands - are case insensitive:
        All - Installs dependencies, V2/CAPE, sets supervisor
        Cuckoo - Install V2/CAPE Cuckoo
        Dependencies - Install all dependencies with performance tricks
        Supervisor - Install supervisor config for CAPE; for v2 use cuckoo --help ;)
        Suricata - Install latest suricata with performance boost
        PostgreSQL - Install latest PostgresSQL
        Yara - Install latest yara
        Mongo - Install latest mongodb
        Dist - will install CAPE distributed stuff
        redsocks2 - install redsocks2
        logrotate - install logrotate config to rotate daily or 10G logs
        Issues - show some known possible bugs/solutions

    Useful links - THEY CAN BE OUTDATED; RTFM!!!
        * https://cuckoo.sh/docs/introduction/index.html
        * https://medium.com/@seifreed/how-to-deploy-cuckoo-sandbox-431a6e65b848
        * https://infosecspeakeasy.org/t/howto-build-a-cuckoo-sandbox/27
    Cuckoo V2 customizations neat howto
        * https://www.adlice.com/cuckoo-sandbox-customization-v2/
EndOfHelp
}

function install_fail2ban() {
    sudo apt install fail2ban -y

    sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
    sudo sed -i /etc/fail2ban/jail.local

    systemctl start fail2ban
    systemctl enable fail2ban


    #https://kifarunix.com/how-to-protect-ssh-server-authentication-with-fail2ban-on-ubuntu-18-04/2/
}

function install_logrotate() {
    # du -sh /var/log/* | sort -hr | head -n10
    # thanks digitalocean.com for the manual
    # https://www.digitalocean.com/community/tutorials/how-to-manage-logfiles-with-logrotate-on-ubuntu-16-04
    if [ ! -f /etc/logrotate.d/doomedraven.conf ]; then
            cat >> /etc/logrotate.d/doomedraven.conf << EOF
/var/log/*.log {
    daily
    missingok
    rotate 7
    compress
    create
    maxsize 10G
}


/var/log/supervisor/*.log {
    daily
    missingok
    rotate 7
    compress
    create
    maxsize 50M
}
EOF
fi

    sudo /usr/sbin/logrotate --force /etc/logrotate.conf
    du -sh /var/log/* | sort -hr | head -n10
    # wipe kern.log
    # cat /dev/null | sudo tee /var/log/kern.log
}

function redsocks2() {
    cd /tmp || return
    sudo apt install -y git libevent-dev libreadline-dev zlib1g-dev libncurses5-dev
    sudo apt install -y libssl1.0-dev 2>/dev/null
    sudo apt install -y libssl-dev 2>/dev/null
    git clone https://github.com/semigodking/redsocks redsocks2 && cd redsocks2
    DISABLE_SHADOWSOCKS=true make -j$(nproc) #ENABLE_STATIC=true
    sudo cp redsocks2 /usr/bin/
}

function distributed() {
    sudo apt install uwsgi -y 2>/dev/null
    sudo mkdir -p /data/{config,}db
    sudo chown mongodb:mongodb /data/ -R
    cat >> /etc/uwsgi/apps-available/cuckoo_api.ini << EOL
[uwsgi]
    plugins = python
    callable = application
    ;change this patch if is different
    chdir = /opt/CAPEv2/utils
    master = true
    mount = /=api.py
    processes = 5
    manage-script-name = true
    socket = 0.0.0.0:8090
    http-timeout = 200
    pidfile = /tmp/api.pid
    ; if you will use with nginx, comment next line
    protocol=http
    enable-threads = true
    lazy-apps = true
    timeout = 600
    chmod-socket = 664
    chown-socket = cuckoo:cuckoo
    gui = cuckoo
    uid = cuckoo
    stats = 127.0.0.1:9191
EOL

    ln -s /etc/uwsgi/apps-available/cuckoo_api.ini /etc/uwsgi/apps-enabled
    service uwsgi restart

    if [ ! -f /etc/systemd/system/mongod.service ]; then
        cat >> /etc/systemd/system/mongod.service <<EOL
# /etc/systemd/system/mongodb.service
[Unit]
Description=High-performance, schema-free document-oriented database
Wants=network.target
After=network.target

[Service]
PermissionsStartOnly=true
ExecStartPre=/bin/mkdir -p /data/{config,}db
ExecStartPre=/bin/chown mongodb:mongodb /data -R
# https://www.tutorialspoint.com/mongodb/mongodb_replication.htm
ExecStart=/usr/bin/numactl --interleave=all /usr/bin/mongod --quiet --shardsvr --port 27017
# --replSet rs0
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
# enable on ramfs servers
# --wiredTigerCacheSizeGB=50
#User=mongodb
#Group=mongodb
#StandardOutput=syslog
#StandardError=syslog
#SyslogIdentifier=mongodb

[Install]
WantedBy=multi-user.target
EOL
fi

    if [ ! -f /etc/systemd/system/mongos.service ]; then
        cat >> /etc/systemd/system/mongos.service << EOL
[Unit]
Description=Mongo shard service
After=network.target
After=bind9.service
[Service]
PIDFile=/var/run/mongos.pid
User=root
ExecStart=/usr/bin/mongos --configdb cuckoo_config/${DIST_MASTER_IP}:27019 --port 27020
[Install]
WantedBy=multi-user.target
EOL
fi

    systemctl daemon-reload
    systemctl enable mongod.service
    systemctl enable mongos.service
    systemctl start mongod.service
    systemctl start mongos.service

    echo -e "\n\n\n[+] CAPE distributed documentation: https://github.com/kevoreilly/CAPEv2/blob/master/docs/book/src/usage/dist.rst"
    echo -e "\t https://docs.mongodb.com/manual/tutorial/enable-authentication/"
    echo -e "\t https://docs.mongodb.com/manual/administration/security-checklist/"
    echo -e "\t https://docs.mongodb.com/manual/core/security-users/#sharding-security"

}

function install_suricata() {
    sudo apt install -y checkinstall libssl-dev liblzma-dev python3 python3-pip python3-distutils libnspr4-dev libnss3-dev jq unzip \
    sqlite3 libsqlite3-dev libreadline-dev libmaxminddb-dev

    # install pcre
    #sudo apt -y install libbz2-1.0 libbz2-dev libbz2-ocaml libbz2-ocaml-dev
    #wget https://ftp.pcre.org/pub/pcre/pcre-8.43.zip
    #unzip pcre-8.43.zip && cd pcre-8.43
    #./configure --prefix=/usr --docdir=/usr/share/doc/pcre-8.43 --enable-unicode-propertiess --enable-pcre16s --enable-pcre32s --enable-pcregrep-libzs --enable-pcregrep-libbz2s --enable-pcretest-libreadlines --disable-static
    #make -j"$(nproc)"
    #sudo checkinstall -D --pkgname=pcre --pkgversion=8.43 --default
    #sudo dpkg -i --force-overwrite pcre_8.43-1_amd64.deb
    #sudo mv -v /usr/lib/libpcre.so.* /lib
    #sudo ln -sfv ../../lib/$(readlink /usr/lib/libpcre.so) /usr/lib/libpcre.so
    #ToDo
    # -- Checking for module 'libpcre>=8.41'
    # Speedup suricata >= 3.1
    # https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Hyperscan
    # https://github.com/01org/hyperscan
    cd /tmp || return
    hyperscan_info=$(curl -s https://api.github.com/repos/intel/hyperscan/releases/latest)
    hyperscan_version=$(echo $hyperscan_info |jq .tag_name|sed "s/\"//g")
    wget -q $(echo $hyperscan_info | jq ".zipball_url" | sed "s/\"//g")
    unzip $hyperscan_version
    directory=`ls | grep "intel-hyperscan-*"`
    cd $directory || return
    #git clone https://github.com/01org/hyperscan.git
    #cd hyperscan/ || return
    mkdir builded
    cd builded || return
    sudo apt install cmake libboost-dev ragel libhtp2 -y
    # doxygen sphinx-common libpcap-dev
    cmake -DBUILD_STATIC_AND_SHARED=1 ../
    # tests
    #bin/unit-hyperscan
    make -j"$(nproc)"
    sudo checkinstall -D --pkgname=hyperscan --default

    echo '[+] Configure Suricata'
    mkdir /var/run/suricata
    sudo chown cuckoo:cuckoo /var/run/suricata -R

    # if we wan suricata with hyperscan:
    sudo apt -y install libpcre3 libpcre3-dbg \
    build-essential autoconf automake libtool libpcap-dev libnet1-dev \
    libyaml-0-2 libyaml-dev zlib1g zlib1g-dev libcap-ng-dev libcap-ng0 \
    make libmagic-dev libjansson-dev libjansson4 pkg-config liblz4-dev \
    python python3-pip libgeoip-dev

    # install rust, cargo
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    source $HOME/.cargo/env
    cargo install cargo-vendor

    sudo apt -y install libnetfilter-queue-dev libnetfilter-queue1 libnfnetlink-dev libnfnetlink0
    pip3 install pyyaml
    echo "/usr/local/lib" | sudo tee --append /etc/ld.so.conf.d/usrlocal.conf
    sudo ldconfig

    #cd /tmp || return
    #wget https://github.com/luigirizzo/netmap/archive/v11.4.zip
    #unzip v11.4.zip
    #cd netmap-* || return
    #./configure
    #make -j"$(getconf _NPROCESSORS_ONLN)"
    suricata_version=5.0.1
    # https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Ubuntu_Installation
    cd /tmp || return
    if [ ! -f suricata-$suricata_version.tar.gz ]; then
        wget https://www.openinfosecfoundation.org/download/suricata-$suricata_version.tar.gz && tar xf suricata-$suricata_version.tar.gz
    fi
    cd suricata-$suricata_version
    #wget "https://www.openinfosecfoundation.org/download/suricata-current.tar.gz"
    #wget "https://www.openinfosecfoundation.org/download/suricata-current.tar.gz.sig"
    #gpg --verify "suricata-current.tar.gz.sig"

    #tar -xzf "suricata-current.tar.gz"
    #rm "suricata-current.tar.gz"
    #directory=`ls -p | grep suricata*/`
    #cd $directory || return
    ./configure --enable-nfqueue --prefix=/usr --sysconfdir=/etc --localstatedir=/var --with-libhs-includes=/usr/local/include/hs/ --with-libhs-libraries=/usr/local/lib/ --enable-profiling --enable-geoip
    make -j"$(getconf _NPROCESSORS_ONLN)" install-full
    # rust doesn't compile with checkinstall
    #sudo checkinstall -D --pkgname=suricata --default
     LD_LIBRARY_PATH=/usr/lib /usr/bin/suricata --build-info|grep Hyperscan
    make install-conf

    cd python || return
    python setup.py build
    python setup.py install
    touch /etc/suricata/threshold.config


    """
    You can now start suricata by running as root something like '/usr/bin/suricata -c /etc/suricata//suricata.yaml -i eth0'.

    If a library like libhtp.so is not found, you can run suricata with:
    LD_LIBRARY_PATH=/usr/lib /usr/bin/suricata -c /etc/suricata//suricata.yaml -i eth0

    While rules are installed now, its highly recommended to use a rule manager for maintaining rules.
    The two most common are Oinkmaster and Pulledpork. For a guide see:
    https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Rule_Management_with_Oinkmaster
    """

    # Download etupdate to update Emerging Threats Open IDS rules:
    sudo pip3 install suricata-update
    mkdir -p "/etc/suricata/rules"
    crontab -l | { cat; echo "15 * * * * sudo /usr/bin/suricata-update --suricata /usr/bin/suricata --suricata-conf /etc/suricata/suricata.yaml -o /etc/suricata/rules/"; } | crontab -
    crontab -l | { cat; echo "15 * * * * /usr/bin/suricatasc -c reload-rules"; } | crontab -

    cp "/usr/share/suricata/rules/*" "/etc/suricata/rules/"

    #change suricata yaml
    sed -i 's|#default-rule-path: /etc/suricata/rules|default-rule-path: /var/lib/suricata/rules|g' /etc/default/suricata
    sed -i 's/#rule-files:/rule-files:/g' /etc/suricata/suricata.yaml
    sed -i 's/# - suricata.rules/ - suricata.rules/g' /etc/suricata/suricata.yaml
    sed -i 's/RUN=yes/RUN=no/g' /etc/default/suricata
    sed -i 's/mpm-algo: ac/mpm-algo: hs/g' /etc/suricata/suricata.yaml
    sed -i 's/mpm-algo: auto/mpm-algo: hs/g' /etc/suricata/suricata.yaml
    sed -i 's/#run-as:/run-as:/g' /etc/suricata/suricata.yaml
    sed -i 's/#  user: suri/   user: cuckoo/g' /etc/suricata/suricata.yaml
    sed -i 's/#  user: suri/   group: cuckoo/g' /etc/suricata/suricata.yaml
    sed -i 's/    depth: 1mb/    depth: 0/g' /etc/suricata/suricata.yaml
    sed -i 's/request-body-limit: 100kb/request-body-limit: 0/g' /etc/suricata/suricata.yaml
    sed -i 's/response-body-limit: 100kb/response-body-limit: 0/g' /etc/suricata/suricata.yaml
    sed -i 's/EXTERNAL_NET: "!$HOME_NET"/EXTERNAL_NET: "ANY"/g' /etc/suricata/suricata.yaml
    # enable eve-log
    python -c "pa = '/etc/suricata/suricata.yaml';q=open(pa, 'rb').read().replace('eve-log:\n      enabled: no\n', 'eve-log:\n      enabled: yes\n');open(pa, 'wb').write(q);"

    chown cuckoo:cuckoo -R /etc/suricata
}


function install_yara() {
    echo '[+] Installing Yara'
    apt install libtool libjansson-dev libmagic1 libmagic-dev jq autoconf checkinstall -y
    cd /tmp/ || return
    yara_info=$(curl -s https://api.github.com/repos/VirusTotal/yara/releases/latest)
    yara_version=$(echo $yara_info |jq .tag_name|sed "s/\"//g")
    yara_repo_url=$(echo $yara_info | jq ".zipball_url" | sed "s/\"//g")
    wget -q $yara_repo_url
    unzip $yara_version
    #wget "https://github.com/VirusTotal/yara/archive/v$yara_version.zip" && unzip "v$yara_version.zip"
    directory=`ls | grep "VirusTotal-yara-*"`
    cd $directory || return
    ./bootstrap.sh
    ./configure --enable-cuckoo --enable-magic --enable-dotnet --enable-profiling
    make -j"$(getconf _NPROCESSORS_ONLN)"
    checkinstall -D --pkgname="yara-$yara_version" --pkgversion="$yara_version|cut -c 2-" --default
    ldconfig
    cd ..
    rm "VirusTotal-yara-*.zip"
    git clone --recursive https://github.com/VirusTotal/yara-python
    cd yara-python || return
    pip3 install .
    pip3 install .
}

function install_mongo(){
    echo "[+] Installing MongoDB"
    wget -qO - https://www.mongodb.org/static/pgp/server-4.2.asc | sudo apt-key add -
    echo "deb [ arch=amd64 ] https://repo.mongodb.org/apt/ubuntu $(lsb_release -cs)/mongodb-org/4.2 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb.list

    apt update 2>/dev/null
    apt install libpcre3-dev
    apt install -y mongodb-org-mongos mongodb-org-server mongodb-org-shell mongodb-org-tools
    pip3 install pymongo -U

    apt install -y ntp
    systemctl start ntp.service && sudo systemctl enable ntp.service

    if ! grep -q -E '^kernel/mm/transparent_hugepage/enabled' /etc/sysfs.conf; then
        sudo apt install sysfsutils -y
        echo "kernel/mm/transparent_hugepage/enabled = never" >> /etc/sysfs.conf
        echo "kernel/mm/transparent_hugepage/defrag = never" >> /etc/sysfs.conf
    fi

    if [ -f /etc/systemd/system/mongod.service ]; then
        systemctl stop mongod.service
        rm /etc/systemd/system/mongod.service
        systemctl daemon-reload
    fi

    if [ ! -f /etc/systemd/system/mongodb.service ]; then
        cat >> /etc/systemd/system/mongodb.service <<EOF
[Unit]
Description=High-performance, schema-free document-oriented database
Wants=network.target
After=network.target
[Service]
PermissionsStartOnly=true
ExecStartPre=/bin/mkdir -p /data/{config,}db
ExecStartPre=/bin/chown mongodb:mongodb /data -R
# https://www.tutorialspoint.com/mongodb/mongodb_replication.htm
ExecStart=/usr/bin/numactl --interleave=all /usr/bin/mongod --quiet --shardsvr --bind_ip_all --port 27017
# --replSet rs0
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
# enable on ramfs servers
# --wiredTigerCacheSizeGB=50
User=mongodb
Group=mongodb
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=mongodb
[Install]
WantedBy=multi-user.target
EOF

    fi
    systemctl enable mongodb.service
    systemctl restart mongodb.service

    echo -n "https://www.percona.com/blog/2016/08/12/tuning-linux-for-mongodb/"
}

function install_postgresql() {
    # Postgresql 12
    wget --quiet -O - https://www.postgresql.org/media/keys/ACCC4CF8.asc | sudo apt-key add -
    echo "deb http://apt.postgresql.org/pub/repos/apt/ `lsb_release -cs`-pgdg main" |sudo tee  /etc/apt/sources.list.d/pgdg.list

    sudo apt update -y
    sudo apt -y install libpq-dev postgresql-12 postgresql-client-12

    pip3 install psycopg2
}

function dependencies() {
    sudo timedatectl set-timezone UTC

    export LANGUAGE=en_US.UTF-8
    export LANG=en_US.UTF-8
    export LC_ALL=en_US.UTF-8

    sudo snap install canonical-livepatch
    #sudo canonical-livepatch enable APITOKEN

    # deps
    apt install psmisc jq sqlite3 tmux net-tools checkinstall graphviz python3-pydot git numactl python3 python3-dev python3-pip python3-m2crypto libjpeg-dev zlib1g-dev -y
    apt install swig upx-ucl libssl-dev wget zip unzip p7zip-full rar unrar unace-nonfree cabextract geoip-database libgeoip-dev libjpeg-dev mono-utils ssdeep libfuzzy-dev exiftool -y
    apt install ssdeep uthash-dev libconfig-dev libarchive-dev libtool autoconf automake privoxy software-properties-common wkhtmltopdf xvfb xfonts-100dpi tcpdump libcap2-bin -y
    apt install python3-pil subversion python3-capstone uwsgi uwsgi-plugin-python python3-pyelftools -y
    #clamav clamav-daemon clamav-freshclam
    # if broken sudo python -m pip uninstall pip && sudo apt install python-pip --reinstall
    #pip3 install --upgrade pip
    # /usr/bin/pip
    # from pip import __main__
    # if __name__ == '__main__':
    #     sys.exit(__main__._main())
    pip3 install supervisor requests[security] pyOpenSSL pefile tldextract httpreplay imagehash oletools olefile networkx>=2.1 mixbox capstone PyCrypto voluptuous xmltodict future python-dateutil requests_file "gevent>=1.2, <1.3" simplejson pyvmomi pyinstaller maec regex xmltodict -U
    pip3 install git+https://github.com/doomedraven/sflock.git git+https://github.com/doomedraven/socks5man.git pyattck==1.0.4 distorm3 openpyxl git+https://github.com/volatilityfoundation/volatility3
    #config parsers
    pip3 install git+https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP.git git+https://github.com/kevthehermit/RATDecoders.git
    # re2
    apt install libre2-dev -y
    #re2 for py3
    pip3 install cython
    pip3 install https://github.com/andreasvc/pyre2/archive/master.zip

    #thanks Jurriaan <3
    pip3 install git+https://github.com/jbremer/peepdf.git

    pip3 install matplotlib==2.2.2 numpy==1.15.0 six==1.11.0 statistics==1.0.3.5 lief==0.9.0

    pip3 install "django>=2.2.6, <3" git+https://github.com/jsocol/django-ratelimit
    pip3 install sqlalchemy sqlalchemy-utils jinja2 markupsafe bottle chardet pygal rarfile jsbeautifier dpkt nose dnspython pytz requests[socks] python-magic geoip pillow java-random python-whois bs4 git+https://github.com/crackinglandia/pype32.git git+https://github.com/kbandla/pydeep.git flask flask-restful flask-sqlalchemy pyvmomi
    apt install -y openjdk-11-jdk-headless
    apt install -y openjdk-8-jdk-headless

    install_postgresql

    # sudo su - postgres
    #psql
    sudo -u postgres -H sh -c "psql -c \"CREATE USER cuckoo WITH PASSWORD '$PASSWD'\"";
    sudo -u postgres -H sh -c "psql -c \"CREATE DATABASE cuckoo\"";
    sudo -u postgres -H sh -c "psql -d \"cuckoo\" -c \"GRANT ALL PRIVILEGES ON DATABASE cuckoo to cuckoo;\""
    #exit

    sudo apt install apparmor-utils -y
    sudo aa-disable /usr/sbin/tcpdump
    # ToDo check if user exits

    useradd -s /bin/bash -d /home/cuckoo/ -m cuckoo
    usermod -G cuckoo -a cuckoo
    groupadd pcap
    usermod -a -G pcap cuckoo
    chgrp pcap /usr/sbin/tcpdump
    setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump

    '''
    cd /tmp/ || return
    git clone https://github.com/rieck/malheur.git
    cd malheur || return
    ./bootstrap
    ./configure --prefix=/usr
    make -j"$(getconf _NPROCESSORS_ONLN)"
    sudo checkinstall -D --pkgname=malheur --default
    dpkg -i malheur_0.6.0-1_amd64.deb
    '''

    # https://www.torproject.org/docs/debian.html.en
    echo "deb http://deb.torproject.org/torproject.org $(lsb_release -cs) main" >> /etc/apt/sources.list
    echo "deb-src http://deb.torproject.org/torproject.org $(lsb_release -cs) main" >> /etc/apt/sources.list
    sudo apt install gnupg2 -y
    gpg --keyserver keys.gnupg.net --recv A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89
    #gpg2 --recv A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89
    #gpg2 --export A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89 | apt-key add -
    wget -qO - https://deb.torproject.org/torproject.org/A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89.asc | sudo apt-key add -
    sudo apt update 2>/dev/null
    apt install tor deb.torproject.org-keyring libzstd1 -y

    sed -i 's/#RunAsDaemon 1/RunAsDaemon 1/g' /etc/tor/torrc

    cat >> /etc/tor/torrc <<EOF
TransPort $IFACE_IP:9040
DNSPort $IFACE_IP:5353
NumCPUs $(getconf _NPROCESSORS_ONLN)
EOF

    #Then restart Tor:
    sudo systemctl enable tor
    sudo systemctl start tor

    #Edit the Privoxy configuration
    #sudo sed -i 's/R#        forward-socks5t             /     127.0.0.1:9050 ./        forward-socks5t             /     127.0.0.1:9050 ./g' /etc/privoxy/config
    #service privoxy restart

    echo "* soft nofile 1048576" >> /etc/security/limits.conf
    echo "* hard nofile 1048576" >> /etc/security/limits.conf
    echo "root soft nofile 1048576" >> /etc/security/limits.conf
    echo "root hard nofile 1048576" >> /etc/security/limits.conf
    echo "fs.file-max = 100000" >> /etc/sysctl.conf
    echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
    echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
    echo "net.ipv6.conf.lo.disable_ipv6 = 1" >> /etc/sysctl.conf
    echo "net.bridge.bridge-nf-call-ip6tables = 0" >> /etc/sysctl.conf
    echo "net.bridge.bridge-nf-call-iptables = 0" >> /etc/sysctl.conf
    echo "net.bridge.bridge-nf-call-arptables = 0" >> /etc/sysctl.conf

    sudo sysctl -p

    ### PDNS
    sudo apt install git binutils-dev libldns-dev libpcap-dev libdate-simple-perl libdatetime-perl libdbd-mysql-perl -y
    cd /tmp || return
    git clone git://github.com/gamelinux/passivedns.git
    cd passivedns/ || return
    autoreconf --install
    ./configure
    make -j"$(getconf _NPROCESSORS_ONLN)"
    sudo checkinstall -D --pkgname=passivedns --default

    #ToDo move to py3
    cd /usr/local/lib/python2.7/dist-packages/volatility || return
    mkdir resources
    cd resources || return
    touch "__init__.py"
    git clone https://github.com/nemequ/lzmat
    cd lzmat || return
    gcc -Wall -fPIC -c lzmat_dec.c
    gcc -shared -Wl,-soname,lzmat_dec.so.1 -o lzmat_dec.so.1.0 lzmat_dec.o
    mv "$(ls)" ..
    cd .. && rm -r lzmat

    cd /tmp || return
    git clone https://github.com/unicorn-engine/unicorn.git
    sudo apt install libglib2.0-dev -y
    cd unicorn || return
    ./make.sh
    sudo ./make.sh install
    pip3 install unicorn Capstone
}

function install_CAPE() {
    cd /opt || return
    git clone https://github.com/kevoreilly/CAPEv2/
    #chown -R root:cuckoo /usr/var/malheur/
    #chmod -R =rwX,g=rwX,o=X /usr/var/malheur/
    # Adapting owner permissions to the cuckoo path folder
    chown cuckoo:cuckoo -R "/opt/CAPEv2/"

    sed -i "s/process_results = on/process_results = off/g" /opt/CAPEv2/conf/cuckoo.conf
    sed -i "s/connection =/connection = postgresql://cuckoo:$PASSWD@localhost:5432/cuckoo/g" /opt/CAPEv2/conf/cuckoo.conf
    sed -i "s/tor = off/tor = on/g" /opt/CAPEv2/conf/cuckoo.conf
    sed -i "s/memory_dump = off/memory_dump = on/g" /opt/CAPEv2/conf/cuckoo.conf
    sed -i "s/achinery = vmwareserver/achinery = kvm/g" /opt/CAPEv2/conf/cuckoo.conf
    sed -i "s/interface = br0/interface = $NETWORK_IFACE/g" /opt/CAPEv2/conf/aux.conf

}

function supervisor() {
    pip3 install supervisor -U
    #### Cuckoo Start at boot

    if [ ! -d /etc/supervisor/conf.d ]; then
	mkdir -p /etc/supervisor/conf.d
    fi

    if [ ! -d /var/log/supervisor ]; then
	mkdir -p /var/log/supervisor
    fi

    if [ ! -f /etc/supervisor/supervisord.conf ]; then
	echo_supervisord_conf > /etc/supervisor/supervisord.conf
    fi

    if [ ! -f /etc/systemd/system/supervisor.service ]; then
        cat >> /etc/systemd/system/supervisor.service <<EOF
[Unit]
Description=Supervisor process control system for UNIX
Documentation=http://supervisord.org
After=network.target

[Service]
ExecStart=/usr/local/bin/supervisord -n -c /etc/supervisor/supervisord.conf
ExecStop=/usr/local/bin/supervisorctl $OPTIONS shutdown
ExecReload=/usr/local/bin/supervisorctl -c /etc/supervisor/supervisord.conf $OPTIONS reload
KillMode=process
Restart=on-failure
RestartSec=50s

[Install]
WantedBy=multi-user.target
EOF
    fi


    cat >> /etc/supervisor/conf.d/cape.conf <<EOF
[program:cape]
command=python3 cuckoo.py
directory=/opt/CAPEv2/
user=cuckoo
priority=200
autostart=true
autorestart=true
stopasgroup=true
stderr_logfile=/var/log/supervisor/cuckoo.err.log
stdout_logfile=/var/log/supervisor/cuckoo.out.log

[program:web]
command=python3 manage.py runserver 0.0.0.0:8000 --insecure
directory=/opt/CAPEv2/web
user=cuckoo
priority=500
autostart=true
autorestart=true
stopasgroup=true
stderr_logfile=/var/log/supervisor/web.err.log
stdout_logfile=/var/log/supervisor/web.out.log

[program:process]
command=python3 process.py -p7 auto
user=cuckoo
priority=300
directory=/opt/CAPEv2/utils
autostart=true
autorestart=true
stopasgroup=true
stderr_logfile=/var/log/supervisor/process.err.log
stdout_logfile=/var/log/supervisor/process.out.log

[program:rooter]
command=python3 rooter.py
directory=/opt/CAPEv2/utils
user=root
startsecs=10
priority = 100
autostart=true
autorestart=true
stopasgroup=true
stderr_logfile=/var/log/supervisor/router.err.log
stdout_logfile=/var/log/supervisor/router.out.log

[group:CAPE]
programs = rooter,web,cape,process

[program:suricata]
command=bash -c "mkdir /var/run/suricata; chown cuckoo:cuckoo /var/run/suricata; LD_LIBRARY_PATH=/usr/local/lib /usr/bin/suricata -c /etc/suricata/suricata.yaml --unix-socket -k none --user cuckoo --group cuckoo"
user=root
autostart=true
autorestart=true
stopasgroup=true
stderr_logfile=/var/log/supervisor/suricata.err.log
stdout_logfile=/var/log/supervisor/suricata.out.log

[program:socks5man]
command=/usr/local/bin/socks5man verify --repeated
autostart=false
user=cuckoo
autorestart=true
stopasgroup=true
stderr_logfile=/var/log/supervisor/socks5man.err.log
stdout_logfile=/var/log/supervisor/socks5man.out.log
EOF


    # fix for too many open files
    python -c "pa = '/etc/supervisor/supervisord.conf';q=open(pa, 'rb').read().replace('[supervisord]\nlogfile=', '[supervisord]\nminfds=1048576 ;\nlogfile=');open(pa, 'wb').write(q);"

    # include conf.d
    python -c "pa = '/etc/supervisor/supervisord.conf';q=open(pa, 'rb').read().replace(';[include]\n;files = relative/directory/*.ini', '[include]\nfiles = conf.d/cape.conf');open(pa, 'wb').write(q);"

    sudo systemctl enable supervisor
    sudo systemctl start supervisor

    #supervisord -c /etc/supervisor/supervisord.conf
    supervisorctl -c /etc/supervisor/supervisord.conf reload

    supervisorctl reread
    supervisorctl update
    # msoffice decrypt encrypted files

}



# Doesn't work ${$1,,}
COMMAND=$(echo "$1"|tr "[A-Z]" "[a-z]")

case $COMMAND in
    '-h')
        usage
        exit 0;;
esac


if [ $# -eq 3 ]; then
    cuckoo_version=$2
    IFACE_IP=$3
elif [ $# -eq 2 ]; then
    cuckoo_version=$2
elif [ $# -eq 0 ]; then
    echo "[-] check --help"
    exit 1
fi

cuckoo_version=$(echo "$cuckoo_version"|tr "[A-Z]" "[a-z]")


#check if start with root
if [ "$EUID" -ne 0 ]; then
   echo 'This script must be run as root'
   exit 1
fi

OS="$(uname -s)"

case "$COMMAND" in
'all')
    dependencies
    install_mongo
    install_suricata
    install_yara
    if [ "$cuckoo_version" = "v2" ]; then
        pip3 install cuckoo
    else
        install_CAPE
    fi
    supervisor
    distributed
    redsocks2
    install_logrotate
    #socksproxies is to start redsocks stuff
    crontab -l | { cat; echo "@reboot /opt/CAPEv2/socksproxies.sh"; } | crontab -
    crontab -l | { cat; echo "@reboot cd /opt/CAPEv2/utils/ && ./smtp_sinkhole.sh"; } | crontab -

    ;;
'supervisor')
    supervisor;;
'suricata')
    install_suricata;;
'yara')
    install_yara;;
'postgresql')
    install_postgresql;;
'cuckoo')
    if [ "$cuckoo_version" = "v2" ]; then
        pip3 install cuckoo
        print "[*] run cuckoo under cuckoo user, NEVER RUN IT AS ROOT!"
    else
        install_CAPE
    fi;;
'dist')
    distributed;;
'fail2ban')
    install_fail2ban;;
'mongo')
    install_mongo;;
'redsocks2')
    redsocks2;;
'dependencies')
    dependencies;;
'logrotate')
    install_logrotate;;
'issues')
    issues;;
*)
    usage;;
esac
