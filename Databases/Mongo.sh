#!/bin/bash

#show how to upgrade old mongo to newer on Debian

function update_install {
    sudo apt-get update
    sudo apt-get install -y mongodb-org
}

function wipe_mongo(){
   dpkg -l|grep mongo| cut -f 3 -d " "|xargs dpkg --remove
}

# mongo 3.4 debian 9 - https://docs.mongodb.com/v3.4/tutorial/install-mongodb-on-debian/
# https://blog.m157q.tw/posts/2018/07/24/upgrade-mongodb-from-3-2-to-3-4-on-debian-9/
# http://repo.mongodb.org/apt/debian/dists/jessie/mongodb-org/3.4/main/binary-amd64/
wget http://security.debian.org/debian-security/pool/updates/main/o/openssl/libssl1.0.0_1.0.1t-1+deb8u11_amd64.deb && dpkg -i libssl1.0.0_1.0.1t-1+deb8u11_amd64.deb
wget http://repo.mongodb.org/apt/debian/dists/jessie/mongodb-org/3.4/main/binary-amd64/mongodb-org-server_3.4.18_amd64.deb && dpkg -i mongodb-org-server_3.4.18_amd64.deb
wget http://repo.mongodb.org/apt/debian/dists/jessie/mongodb-org/3.4/main/binary-amd64/mongodb-org-shell_3.4.20_amd64.deb && dpkg -i mongodb-org-shell_3.4.20_amd64.deb
mongo --eval 'db.adminCommand({setFeatureCompatibilityVersion: "3.4"})'

# mongo3.6
wipe_mongo
sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv 2930ADAE8CAF5059EE73BB4B58712A2291FA4AD5
echo "deb http://repo.mongodb.org/apt/debian stretch/mongodb-org/3.6 main" | sudo tee /etc/apt/sources.list.d/mongodb-org-3.6.list
update_install
mongo --eval 'db.adminCommand( { getParameter: 1, featureCompatibilityVersion: 1 } )'
mongo --eval 'db.adminCommand({setFeatureCompatibilityVersion: "3.6"})'

# mongo 4
wipe_mongo
rm /etc/apt/sources.list.d/mongodb-org-3.6.list
sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv 9DA31620334BD75D9DCB49F368818C72E52529D4
echo "deb http://repo.mongodb.org/apt/debian stretch/mongodb-org/4.0 main" | sudo tee /etc/apt/sources.list.d/mongodb-org-4.0.list
update_install
sudo systemctl unmask mongodb
systemctl start mongo
