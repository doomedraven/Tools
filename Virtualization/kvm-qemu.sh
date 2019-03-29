#!/bin/bash
#ToDo investigate
#https://www.jamescoyle.net/how-to/1810-qcow2-disk-images-and-performance
#when backing storage is attached to virtio_blk (vda, vdb, etc.) storage controller - performance from iSCSI client connecting to the iSCSI target was in my environment ~ 20 IOPS, with throughput (depending on IO size) ~ 2-3 MiB/s. I changed virtual disk controller within virtual machine to SCSI and I'm able to get 1000+ IOPS and throughput 100+ MiB/s from my iSCSI clients.

#https://linux.die.net/man/1/qemu-img
#"cluster_size"
#Changes the qcow2 cluster size (must be between 512 and 2M). Smaller cluster sizes can improve the image file size whereas larger cluster sizes generally provide better performance.


# https://www.doomedraven.com/2016/05/kvm.html
# Use Ubuntu 18.04 LTS

# https://github.com/dylanaraps/pure-bash-bible
# https://www.shellcheck.net/

# ACPI tables related
# https://wiki.archlinux.org/index.php/DSDT
# Dump on linux
#   acpidump > acpidump.out
# Dump on Windows
#    https://acpica.org/downloads/binary-tools
#    acpixtract -a acpi/4/acpi.dump

# acpixtract -a acpidump.out
# iasl -d DSDT.dat
# Decompile: iasl -d dsdt.dat
# Recompile: iasl -tc dsdt.dsl

#      strs[0] = "KVMKVMKVM\0\0\0"; /* KVM */
#      strs[1] = "Microsoft Hv"; /* Microsoft Hyper-V or Windows Virtual PC */
#      strs[2] = "VMwareVMware"; /* VMware */
#      strs[3] = "XenVMMXenVMM"; /* Xen */
#      strs[4] = "prl hyperv  "; /* Parallels */
#      strs[5] = "VBoxVBoxVBox"; /* VirtualBox */

#https://www.qemu.org/download/#source or https://download.qemu.org/
qemu_version=3.1.0
# libvirt - https://libvirt.org/sources/
# changelog - https://libvirt.org/news.html
libvirt_version=5.1.0
# virt-manager - https://github.com/virt-manager/virt-manager/releases
virt_manager_version=2.1.0
# http://download.libguestfs.org/
libguestfs_version=1.40.2
# autofilled
OS=""
username=""

function changelog() {
cat << EndOfCL
    # 24.02.2019 - Add support for Linux TCP BBR - https://www.cyberciti.biz/cloud-computing/increase-your-linux-server-internet-speed-with-tcp-bbr-congestion-control/
    # 11.02.2019 - Depricated linked clones and added WebVirtMgr
    # 30.01.2019 - Libvirt 5.0.0
    # 27.12.2018 - libguestfs 1.38
    # 10.11.2018 - Virt-manager 2, libivrt-4.10, fixes
    # 11.09.2018 - code improvement
    # 09.09.2018 - ACPI fixes - huge thanks to @2sec4u and @seifreed  for your patience and your time/help :P
    # 05.09.2018 - libivrt 4.7 and virtlogd
    # 19.08.2018 - Intel HAXM notes
    # 14.08.2018 - QEMU 3 support tested on ubuntu 18.04
    # 03.08.2018 - More anti-anti by Tim Shelton (redsand) @ HAWK (hawk.io) and @http_error_418
    # 28.02.2018 - Support for qemu 2.12
EndOfCL
}

function usage() {
cat << EndOfHelp
    Usage: $0 <func_name> <args>
    Commands - are case insensitive:
        All - <username_optional> - Execs QEMU/SeaBios/KVM, username is optional
        QEMU - Install QEMU from source
        SeaBios - Install SeaBios and repalce QEMU bios file
        KVM - this will install intel-HAXM if you on Mac
        HAXM - Mac Hardware Accelerated Execution Manager
        tcp_bbr - Enable TCP BBR congestion control
            * https://www.cyberciti.biz/cloud-computing/increase-your-linux-server-internet-speed-with-tcp-bbr-congestion-control/
        WebVirtMgr - Install WebManager for KVM
        Clone - <VM_NAME> <path_to_hdd> <start_from_number> <#vm_to_create> <path_where_to_store> <network_range_base>
                * Example Win7x64 /VMs/Win7x64.qcow2 0 5 /var/lib/libvirt/images/ 192.168.1
                https://wiki.qemu.org/Documentation/CreateSnapshot
        Libvirt <username_optional> - install libvirt, username is optional
        Libguestfs - install libguestfs
        Replace_qemu - only fix antivms in QEMU source
        Replace_seabios <path> - only fix antivms in SeaBios source
        Issues - will give you error - solution list
        noip - Install No-ip deamon and enable on boot

    Tips:
        * Latest kernels having some KVM features :)
            * apt search linux-image
        * QCOW2 allocations types performance
            * https://www.jamescoyle.net/how-to/1810-qcow2-disk-images-and-performance
            * https://www.jamescoyle.net/how-to/2060-qcow2-physical-size-with-different-preallocation-settings
EndOfHelp
}

function _enable_tcp_bbr() {
    # https://www.cyberciti.biz/cloud-computing/increase-your-linux-server-internet-speed-with-tcp-bbr-congestion-control/
    # grep 'CONFIG_TCP_CONG_BBR' /boot/config-$(uname -r)
    # grep 'CONFIG_NET_SCH_FQ' /boot/config-$(uname -r)
    # egrep 'CONFIG_TCP_CONG_BBR|CONFIG_NET_SCH_FQ' /boot/config-$(uname -r)
    echo "net.core.default_qdisc=fq" >> /etc/security/limits.conf
    echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/security/limits.conf

    sudo sysctl --system
}

function _check_brew() {
    if [ ! -f /usr/local/bin/brew ]; then
        /usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
    fi
}

function install_haxm_mac() {
    _check_brew
    brew cask install intel-haxm
    brew tap jeffreywildman/homebrew-virt-manager
    brew cask install xquartz
    brew install virt-manager virt-viewer

    if [ "$SHELL" = "/bin/zsh" ] || [ "$SHELL" = "/usr/bin/zsh" ] ; then
        echo "export LIBVIRT_DEFAULT_URI=qemu:///system" >> "$HOME/.zsh"
    else
        echo "export LIBVIRT_DEFAULT_URI=qemu:///system" >> "$HOME/.bashrc"
    fi
}

function install_libguestfs() {

    echo "[+] Check for previous version of LibGuestFS"
    sudo dpkg --purge --force-all "libguestfs-*" 2>/dev/null

    sudo apt install gperf flex bison libaugeas-dev libhivex-dev supermin ocaml-nox libhivex-ocaml genisoimage libhivex-ocaml-dev libmagic-dev libjansson-dev -y 2>/dev/null
    cd /tmp || return
    wget "http://download.libguestfs.org/1.40-stable/libguestfs-$libguestfs_version.tar.gz"
    tar xf "libguestfs-$libguestfs_version.tar.gz"
    cd libguestfs-$libguestfs_version
    ./configure
    make -j"$(getconf _NPROCESSORS_ONLN)"
    REALLY_INSTALL=yes checkinstall -D --pkgname=libvirt-$libguestfs_version --default
    # ln -s /usr/local/lib/libguestfs.so.0 /lib/x86_64-linux-gnu/libguestfs.so.0
}

function install_libvirt() {
    # http://ask.xmodulo.com/compile-virt-manager-debian-ubuntu.html
    #rm -r /usr/local/lib/python2.7/dist-packages/libvirt*

    # set to hold to avoid side problems
    cat >> /etc/apt/preferences.d/doomedraven << EOH
Package: libvirt-bin
Pin: release *
Pin-Priority: -1
 Package: libvirt0
Pin: release *
Pin-Priority: -1
EOH

    echo "[+] Checking/deleting old versions of Libvirt"
    apt-get purge libvirt0 libvirt-bin 2>/dev/null
    dpkg -l|grep "libvirt-[0-9]\{1,2\}\.[0-9]\{1,2\}\.[0-9]\{1,2\}"|cut -d " " -f 3|sudo xargs dpkg --purge --force-all 2>/dev/null

    cd /tmp || return
    if [ -f  libvirt-$libvirt_version.tar.xz ]; then
        rm -r libvirt-$libvirt_version
    else
        wget https://libvirt.org/sources/libvirt-$libvirt_version.tar.xz
    fi
    tar xf libvirt-$libvirt_version.tar.xz
    cd libvirt-$libvirt_version || return
    if [ "$OS" = "Linux" ]; then
        apt-get install python-dev python3-dev unzip numad glib-2.0 libglib2.0-dev libsdl1.2-dev lvm2 python-pip python-libxml2 python3-libxml2 ebtables libosinfo-1.0-dev libnl-3-dev libnl-route-3-dev libyajl-dev xsltproc libapparmor-dev libdevmapper-dev libpciaccess-dev apparmor-utils -y 2>/dev/null
        pip install ipaddr
        # --prefix=/usr --localstatedir=/var --sysconfdir=/etc
        ./autogen.sh --system  --with-qemu=yes --with-dtrace --with-numad --with-storage-rbd  --disable-nls --with-openvz=no --with-vmware=no --with-phyp=no --with-xenapi=no --with-libxl=no  --with-vbox=no --with-lxc=no --with-vz=no   --with-esx=no --with-hyperv=no --with-yajl=yes --with-secdriver-apparmor=yes --with-apparmor-profiles --with-apparmor-profiles
        make -j"$(getconf _NPROCESSORS_ONLN)"
        checkinstall -D --pkgname=libvirt-$libvirt_version --default
        #make -j"$(getconf _NPROCESSORS_ONLN)" install
    elif [ "$OS" = "Darwin" ]; then
        ./autogen.sh --system --prefix=/usr/local/ --localstatedir=/var --sysconfdir=/etc --with-qemu=yes --with-dtrace --disable-nls --with-openvz=no --with-vmware=no --with-phyp=no --with-xenapi=no --with-libxl=no  --with-vbox=no --with-lxc=no --with-vz=no   --with-esx=no --with-hyperv=no --with-wireshark-dissector=no --with-yajl=yes
    fi

    # https://wiki.archlinux.org/index.php/Libvirt#Using_polkit
    if [ -f /etc/libvirt/libvirtd.conf ]; then
        path="/etc/libvirt/libvirtd.conf"
    elif [ -f /usr/local/etc/libvirt/libvirtd.conf ]; then
        path="/usr/local/etc/libvirt/libvirtd.conf"
    fi

    sed -i 's/#unix_sock_group/unix_sock_group/g' $path
    sed -i 's/#unix_sock_ro_perms = "0777"/unix_sock_ro_perms = "0770"/g' $path
    sed -i 's/#unix_sock_rw_perms = "0770"/unix_sock_rw_perms = "0770"/g' $path
    sed -i 's/#auth_unix_ro = "none"/auth_unix_ro = "none"/g' $path
    sed -i 's/#auth_unix_rw = "none"/auth_unix_rw = "none"/g' $path

    # https://gitlab.com/apparmor/apparmor/wikis/Libvirt
    echo "[+] Setting AppArmor for libvirt/kvm/qemu"
    sed -i 's/#security_driver = "selinux"/security_driver = "apparmor"/g' /etc/libvirt/qemu.conf
    aa-complain /usr/sbin/libvirtd

    cd /tmp || return

    if [ ! -f v$libvirt_version.zip ]; then
        wget https://github.com/libvirt/libvirt-python/archive/v$libvirt_version.zip
    fi
    unzip v$libvirt_version.zip
    cd libvirt-python* || return
    python3 setup.py build
    python3 setup.py install
    # CAPE will use this lib so we can compile it with python2 too
    python setup.py build
    python setup.py install
    if [ "$OS" = "Linux" ]; then
        # https://github.com/libvirt/libvirt/commit/e94979e901517af9fdde358d7b7c92cc055dd50c
        groupname=""
        if grep -q -E '^libvirtd:' /etc/group; then
            groupname="libvirtd"
        elif grep -q -E '^libvirt:' /etc/group; then
            groupname="libvirt"
        else
            # create group if missed
            groupname="libvirt"
            groupadd libvirt
        fi
        usermod -G $groupname -a "$(whoami)"
        if "$username"; then
            usermod -G $groupname -a "$username"
        fi
        echo "[+] You should logout and login "
    fi

}

function install_kvm_linux_apt() {
    #sed -i 's/# deb-src/deb-src/g' /etc/apt/sources.list
    apt-get update 2>/dev/null
    apt-get install build-essential python-pip python-pip3 gcc pkg-config cpu-checker intltool -y 2>/dev/null
    apt-get install gtk-update-icon-cache -y 2>/dev/null

    # WSL support
    apt-get install gcc make gnutls-bin -y
    # remove old
    apt-get purge libvirt0 libvirt-bin -y
    install_libvirt

    systemctl enable libvirtd.service
    systemctl restart libvirtd.service
    systemctl enable virtlogd.socket
    systemctl restart virtlogd.socket

    # from build-dep
    apt install libgirepository1.0-dev gtk-doc-tools python-pip python3-pip gir1.2-govirt-1.0 libgovirt-dev \
    libgovirt-common libgovirt2 gir1.2-rest-0.7 unzip intltool augeas-doc ifupdown wodim cdrkit-doc indicator-application \
    augeas-tools radvd auditd systemtap nfs-common zfsutils pm-utils python-openssl-doc python-socks python-ntlm samba ovmf \
    debootstrap sharutils-doc ssh-askpass gnome-keyring python-requests python-six python-urllib3 python2.7 python2.7-minimal \
    sharutils spice-client-glib-usb-acl-helper ubuntu-mono x11-common python-cryptography python-dbus python-enum34 python-gi \
    python-gi-cairo python-idna python-ipaddr python-ipaddress  python-libxml2 python3-libxml2 python-minimal python-openssl python-pkg-resources \
    libxml2-utils libxrandr2 libxrender1 libxshmfence1 libxtst6 libxv1 libyajl2 msr-tools osinfo-db python python-asn1crypto \
    python-cairo python-certifi python-cffi-backend python-chardet libxcb-present0 libxcb-render0 libxcb-shm0 libxcb-sync1 \
    libxcb-xfixes0 libxcomposite1 libxcursor1 libxdamage1 libxen-4.9 libxenstore3.0 libxfixes3 libxft2 libxi6 libxinerama1 \
    libxkbcommon0 libusbredirhost1 libusbredirparser1 libv4l-0 libv4lconvert0 libvisual-0.4-0 libvorbis0a libvorbisenc2 libvpx5 \
    libvte-2.91-0 libvte-2.91-common libwavpack1 libwayland-client0 libwayland-cursor0 libwayland-egl1-mesa libwayland-server0 \
    libx11-xcb1 libxcb-dri2-0 libxcb-dri3-0 libsoup-gnome2.4-1 libsoup2.4-1 libspeex1 libspice-client-glib-2.0-8 \
    libspice-client-gtk-3.0-5 libspice-server1 libtag1v5 libtag1v5-vanilla libthai-data libthai0 libtheora0 libtiff5 \
    libtwolame0 libpython2.7 libpython2.7-minimal libpython2.7-stdlib librados2 libraw1394-11 librbd1 librdmacm1 librest-0.7-0 \
    librsvg2-2 librsvg2-common libsamplerate0 libsdl1.2debian libshout3 libsndfile1 libpango-1.0-0 libpangocairo-1.0-0 \
    libpangoft2-1.0-0 libpangoxft-1.0-0 libpciaccess0 libphodav-2.0-0 libphodav-2.0-common libpixman-1-0 libproxy1v5 \
    libpulse-mainloop-glib0 libpulse0 libpython-stdlib libgstreamer1.0-0 libgtk-3-0 libgtk-3-bin libgtk-3-common libgtk-vnc-2.0-0 \
    libgudev-1.0-0 libgvnc-1.0-0 libharfbuzz0b libibverbs1 libiec61883-0 libindicator3-7 libiscsi7 libjack-jackd2-0 libjbig0 \
    libjpeg-turbo8 libjpeg8 libjson-glib-1.0-0 libjson-glib-1.0-common liblcms2-2 libmp3lame0 libmpg123-0 libnetcf1 libnl-route-3-200 \
    libnspr4 libnss3 libogg0 libopus0 liborc-0.4-0 libosinfo-1.0-0 libcairo-gobject2 libcairo2 libcdparanoia0 libcolord2 libcroco3 \
    libcups2 libdatrie1 libdbusmenu-glib4 libdbusmenu-gtk3-4 libdconf1 libdv4 libegl-mesa0 libegl1 libepoxy0 libfdt1 libflac8 \
    libfontconfig1 libgbm1 libgdk-pixbuf2.0-0 libgdk-pixbuf2.0-bin libgdk-pixbuf2.0-common libglapi-mesa libglvnd0  libgraphite2-3 \
    libgstreamer-plugins-base1.0-0 libgstreamer-plugins-good1.0-0 gtk-update-icon-cache hicolor-icon-theme humanity-icon-theme \
    ibverbs-providers  libaa1 libaio1 libappindicator3-1 libasound2 libasound2-data libasyncns0 libatk-bridge2.0-0 libatk1.0-0 \
    libatk1.0-data libatspi2.0-0 libaugeas0 libavahi-client3 libavahi-common-data libavahi-common3 libavc1394-0 libbluetooth3 \
    libbrlapi0.6 libcaca0 libcacard0 gir1.2-atk-1.0 gir1.2-freedesktop gir1.2-gdkpixbuf-2.0 gir1.2-gtk-3.0 gir1.2-gtk-vnc-2.0 \
    gir1.2-libosinfo-1.0  gir1.2-pango-1.0 gir1.2-spiceclientglib-2.0 gir1.2-spiceclientgtk-3.0 gir1.2-vte-2.91 glib-networking \
    glib-networking-common glib-networking-services gsettings-desktop-schemas gstreamer1.0-plugins-base gstreamer1.0-plugins-good \
    gstreamer1.0-x adwaita-icon-theme at-spi2-core augeas-lenses bridge-utils cpu-checker dconf-gsettings-backend dconf-service \
    fontconfig fontconfig-config fonts-dejavu-core genisoimage gir1.2-appindicator3-0.1 gir1.2-secret-1 -y 2>/dev/null
    # should be installed first

    pip install pycairo
    pip3 install pycairo
    pip3 install PyGObject -U
    pip install PyGObject -U

    cd /tmp || return
    if wget https://libvirt.org/sources/glib/libvirt-glib-1.0.0.tar.gz; then
        tar xf libvirt-glib-1.0.0.tar.gz
        cd libvirt-glib-1.0.0
        aclocal && libtoolize --force
        automake --add-missing
        ./configure
        make -j"$(getconf _NPROCESSORS_ONLN)"
        checkinstall --pkgname=libvirt-glib-1.0-0 --default
        wget http://launchpadlibrarian.net/297448356/gir1.2-libvirt-glib-1.0_1.0.0-1_amd64.deb
        dpkg -i gir1.2-libvirt-glib-1.0_1.0.0-1_amd64.deb
        #apt-get install gir1.2-libvirt-glib-1.0 -y

        /sbin/ldconfig
    fi

    if [ ! -f "virt-manager" ]; then
        #git clone -b v1.5-maint https://github.com/virt-manager/virt-manager.git
        git clone https://github.com/virt-manager/virt-manager.git
    fi
    cd "virt-manager" || return
    apt-get install gobject-introspection intltool pkg-config python-lxml python3-libxml2 libxml2-dev libxslt-dev python-dev gir1.2-gtk-vnc-2.0 gir1.2-spiceclientgtk-3.0 libgtk-3-dev -y
    # py3
    python3 setup.py build
    python3 setup.py install
    if [ "$SHELL" = "/bin/zsh" ] || [ "$SHELL" = "/usr/bin/zsh" ] ; then
        echo "export LIBVIRT_DEFAULT_URI=qemu:///system" >> "$HOME/.zsh"
    else
        echo "export LIBVIRT_DEFAULT_URI=qemu:///system" >> "$HOME/.bashrc"
    fi
    #reboot me here
    kvm-ok
}


function replace_qemu_clues_public() {
    echo '[+] Patching QEMU clues'
    if ! sed -i 's/QEMU HARDDISK/<WOOT> HARDDISK/g' qemu*/hw/ide/core.c; then
        echo 'QEMU HARDDISK was not replaced in core.c'; fail=1
    fi
    if ! sed -i 's/QEMU HARDDISK/<WOOT> HARDDISK/g' qemu*/hw/scsi/scsi-disk.c; then
        echo 'QEMU HARDDISK was not replaced in scsi-disk.c'; fail=1
    fi
    if ! sed -i 's/QEMU DVD-ROM/<WOOT> DVD-ROM/g' qemu*/hw/ide/core.c; then
        echo 'QEMU DVD-ROM was not replaced in core.c'; fail=1
    fi
    if ! sed -i 's/QEMU DVD-ROM/<WOOT> DVD-ROM/g' qemu*/hw/ide/atapi.c; then
        echo 'QEMU DVD-ROM was not replaced in atapi.c'; fail=1
    fi
    if ! sed -i 's/s->vendor = g_strdup("QEMU");/s->vendor = g_strdup("<WOOT>");/g' qemu*/hw/scsi/scsi-disk.c; then
        echo 'Vendor string was not replaced in scsi-disk.c'; fail=1
    fi
    if ! sed -i 's/QEMU CD-ROM/<WOOT> CD-ROM/g' qemu*/hw/scsi/scsi-disk.c; then
        echo 'QEMU CD-ROM was not patched in scsi-disk.c'; fail=1
    fi
    if ! sed -i 's/padstr8(buf + 8, 8, "QEMU");/padstr8(buf + 8, 8, "<WOOT>");/g' qemu*/hw/ide/atapi.c; then
        echo 'padstr was not replaced in atapi.c'; fail=1
    fi
    if ! sed -i 's/QEMU MICRODRIVE/<WOOT> MICRODRIVE/g' qemu*/hw/ide/core.c; then
        echo 'QEMU MICRODRIVE was not replaced in core.c'; fail=1
    fi
    if ! sed -i 's/KVMKVMKVM\\0\\0\\0/GenuineIntel/g' qemu*/target/i386/kvm.c; then
        echo 'KVMKVMKVM was not replaced in kvm.c'; fail=1
    fi
	# by @http_error_418
    #if  sed -i 's/Microsoft Hv/GenuineIntel/g' qemu*/target/i386/kvm.c; then
    #    echo 'Microsoft Hv was not replaced in target/i386/kvm.c'; fail=1
    #fi
    if ! sed -i 's/"bochs"/"hawks"/g' qemu*/block/bochs.c; then
        echo 'BOCHS was not replaced in block/bochs.c'; fail=1
    fi
    # by Tim Shelton (redsand) @ HAWK (hawk.io)
    if ! sed -i 's/"BOCHS "/"ALASKA"/g' qemu*/include/hw/acpi/aml-build.h; then
        echo 'bochs was not replaced in include/hw/acpi/aml-build.h'; fail=1
    fi
    # by Tim Shelton (redsand) @ HAWK (hawk.io)
    if ! sed -i 's/Bochs Pseudo/Intel RealTime/g' qemu*/roms/ipxe/src/drivers/net/pnic.c; then
        echo 'Bochs Pseudo was not replaced in roms/ipxe/src/drivers/net/pnic.c'; fail=1
    fi
    # by Tim Shelton (redsand) @ HAWK (hawk.io)
    #if ! sed -i 's/Bochs\/Plex86/<WOOT>\/FIRM64/g' qemu*/roms/vgabios/vbe.c; then
    #    echo 'BOCHS was not replaced in roms/vgabios/vbe.c'; fail=1
    #fi
}

function replace_seabios_clues_public() {
    echo "[+] Generating SeaBios Kconfig"
    echo "[+] Fixing SeaBios antivms"
    if ! sed -i 's/Bochs/<WOOT>/g' src/config.h; then
        echo 'Bochs was not replaced in src/config.h'; fail=1
    fi
    if ! sed -i 's/BOCHSCPU/<WOOT>/g' src/config.h; then
        echo 'BOCHSCPU was not replaced in src/config.h'; fail=1
    fi
    if ! sed -i 's/"BOCHS "/"<WOOT>"/g' src/config.h; then
        echo 'BOCHS was not replaced in src/config.h'; fail=1
    fi
    if ! sed -i 's/BXPC/<WOOT>/g' src/config.h; then
        echo 'BXPC was not replaced in src/config.h'; fail=1
    fi
    if ! sed -i 's/QEMU0001/<WOOT>/g' src/fw/ssdt-misc.dsl; then
        echo 'QEMU0001 was not replaced in src/fw/ssdt-misc.dsl'; fail=1
    fi
    if ! sed -i 's/QEMU\/Bochs/<WOOT>\/<WOOT>/g' vgasrc/Kconfig; then
        echo 'QEMU\/Bochs was not replaced in vgasrc/Kconfig'; fail=1
    fi
    if ! sed -i 's/qemu /<WOOT> /g' vgasrc/Kconfig; then
        echo 'qemu was not replaced in vgasrc/Kconfig'; fail=1
    fi

    FILES=(
        src/hw/blockcmd.c
        src/fw/paravirt.c
    )
    for file in "${FILES[@]}"; do
        if ! sed -i 's/"QEMU/"<WOOT>/g' "$file"; then
            echo "QEMU was not replaced in $file"; fail=1
        fi
    done
    if ! sed -i 's/"QEMU"/"<WOOT>"/g' src/hw/blockcmd.c; then
        echo '"QEMU" was not replaced in  src/hw/blockcmd.c'; fail=1
    fi
    FILES=(
        "src/fw/acpi-dsdt.dsl"
        "src/fw/q35-acpi-dsdt.dsl"
    )
    for file in "${FILES[@]}"; do
        if ! sed -i 's/"BXPC"/"<WOOT>"/g' "$file"; then
            echo "BXPC was not replaced in $file"; fail=1
        fi
        if ! sed -i 's/"BXDSDT"/"<WOOT>"/g' "$file"; then
            echo "BXDSDT was not replaced in $file"; fail=1
        fi
    done
    if ! sed -i 's/"BXPC"/"<WOOT>"/g' "src/fw/ssdt-pcihp.dsl"; then
        echo 'BXPC was not replaced in src/fw/ssdt-pcihp.dsl'; fail=1
    fi
    if ! sed -i 's/"BXDSDT"/"<WOOT>"/g' "src/fw/ssdt-pcihp.dsl"; then
        echo 'BXDSDT was not replaced in src/fw/ssdt-pcihp.dsl'; fail=1
    fi
    if ! sed -i 's/"BXPC"/"<WOOT>"/g' "src/fw/ssdt-proc.dsl"; then
        echo 'BXPC was not replaced in "src/fw/ssdt-proc.dsl"'; fail=1
    fi
    if ! sed -i 's/"BXSSDT"/"<WOOT>"/g' "src/fw/ssdt-proc.dsl"; then
        echo 'BXSSDT was not replaced in src/fw/ssdt-proc.dsl'; fail=1
    fi
    if ! sed -i 's/"BXPC"/"<WOOT>"/g' "src/fw/ssdt-misc.dsl"; then
        echo 'BXPC was not replaced in src/fw/ssdt-misc.dsl'; fail=1
    fi
    if ! sed -i 's/"BXSSDTSU"/"<WOOT>"/g' "src/fw/ssdt-misc.dsl"; then
        echo 'BXDSDT was not replaced in src/fw/ssdt-misc.dsl'; fail=1
    fi
    if ! sed -i 's/"BXSSDTSUSP"/"<WOOT>"/g' src/fw/ssdt-misc.dsl; then
        echo 'BXSSDTSUSP was not replaced in src/fw/ssdt-misc.dsl'; fail=1
    fi
    if ! sed -i 's/"BXSSDT"/"<WOOT>"/g' src/fw/ssdt-proc.dsl; then
        echo 'BXSSDT was not replaced in src/fw/ssdt-proc.dsl'; fail=1
    fi
    if ! sed -i 's/"BXSSDTPCIHP"/"<WOOT>"/g' src/fw/ssdt-pcihp.dsl; then
        echo 'BXPC was not replaced in src/fw/ssdt-pcihp.dsl'; fail=1
    fi
    FILES=(
        src/fw/q35-acpi-dsdt.dsl
        src/fw/acpi-dsdt.dsl
        src/fw/ssdt-misc.dsl
        src/fw/ssdt-proc.dsl
        src/fw/ssdt-pcihp.dsl
        src/config.h
    )
    for file in "${FILES[@]}"; do
        if ! sed -i 's/"BXPC"/"A M I"/g' "$file"; then
            echo "BXPC was not replaced in $file"; fail=1
        fi
    done
}

function qemu_func() {
    cd /tmp || return

    echo '[+] Cleaning QEMU old install if exists'
    rm -r /usr/share/qemu >/dev/null 2>&1
    dpkg -r ubuntu-vm-builder python-vm-builder >/dev/null 2>&1
    dpkg -l |grep qemu |cut -d " " -f 3|xargs dpkg --purge --force-all >/dev/null 2>&1

    echo '[+] Downloading QEMU source code'
    if [ ! -f qemu-$qemu_version.tar.xz ]; then
        wget "https://download.qemu.org/qemu-$qemu_version.tar.xz"
    fi

    if [ ! -f qemu-$qemu_version.tar.xz ]; then
        echo "[-] Download qemu-$qemu_version failed"
        exit
    fi

    if ! $(tar xf "qemu-$qemu_version.tar.xz") ; then
        echo "[-] Failed to extract, check if download was correct"
        exit 1
    fi
    fail=0

    if [ "$OS" = "Linux" ]; then
        add-apt-repository universe
        apt-get update
        apt-get install checkinstall openbios-* libssh2-1-dev vde2 liblzo2-dev libghc-gtk3-dev libsnappy-dev libbz2-dev libxml2-dev google-perftools libgoogle-perftools-dev libvde-dev -y 2>/dev/null
        apt-get install debhelper ibusb-1.0-0-dev libxen-dev uuid-dev xfslibs-dev libjpeg-dev libusbredirparser-dev device-tree-compiler texinfo libbluetooth-dev libbrlapi-dev libcap-ng-dev libcurl4-gnutls-dev libfdt-dev gnutls-dev libiscsi-dev libncurses5-dev libnuma-dev libcacard-dev librados-dev librbd-dev libsasl2-dev libseccomp-dev libspice-server-dev \
        libaio-dev libcap-dev libattr1-dev libpixman-1-dev libgtk2.0-bin  libxml2-utils systemtap-sdt-dev -y 2>/dev/null

    elif [ "$OS" = "Darwin" ]; then
        _check_brew
        brew install pkg-config libtool jpeg gnutls glib ncurses pixman libpng vde gtk+3 libssh2 libssh2 libvirt snappy libcapn gperftools glib -y
    fi
    # WOOT
    # some checks may be depricated, but keeping them for compatibility with old versions

    #if [ $? -eq 0 ]; then
        if declare -f -F "replace_qemu_clues"; then
            replace_qemu_clues
        else
            replace_qemu_clues_public
        fi
        if [ $fail -eq 0 ]; then
            echo '[+] Starting compile it'
            cd qemu-$qemu_version || return
	        # add in future --enable-netmap https://sgros-students.blogspot.com/2016/05/installing-and-testing-netmap.html
            # remove --target-list=i386-softmmu,x86_64-softmmu,i386-linux-user,x86_64-linux-user  if you want all targets
            if [ "$OS" = "Linux" ]; then
                # --target-list=i386-softmmu,x86_64-softmmu,i386-linux-user,x86_64-linux-user
                ./configure --prefix=/usr --libexecdir=/usr/lib/qemu --localstatedir=/var --bindir=/usr/bin/ --enable-gnutls --enable-docs --enable-gtk --enable-vnc --enable-vnc-sasl --enable-vnc-png --enable-vnc-jpeg --enable-curl --enable-kvm  --enable-linux-aio --enable-cap-ng --enable-vhost-net --enable-vhost-crypto --enable-spice --enable-usb-redir --enable-lzo --enable-snappy --enable-bzip2 --enable-coroutine-pool --enable-libssh2 --enable-libxml2 --enable-tcmalloc --enable-replication --enable-tools --enable-capstone
            elif [ "$OS" = "Darwin" ]; then
                # --enable-vhost-net --enable-vhost-crypto
                ./configure --prefix=/usr --libexecdir=/usr/lib/qemu --localstatedir=/var --bindir=/usr/bin/ --enable-gnutls --enable-docs  --enable-vnc --enable-vnc-sasl --enable-vnc-png --enable-vnc-jpeg --enable-curl --enable-hax --enable-usb-redir --enable-lzo --enable-snappy --enable-bzip2 --enable-coroutine-pool  --enable-libxml2 --enable-tcmalloc --enable-replication --enable-tools --enable-capstone
            fi
            if  [ $? -eq 0 ]; then
                echo '[+] Starting Install it'
                #dpkg -i qemu*.deb
                if [ -f /usr/share/qemu/qemu_logo_no_text.svg ]; then
                    rm /usr/share/qemu/qemu_logo_no_text.svg
                fi
                make -j"$(getconf _NPROCESSORS_ONLN)"
                if [ "$OS" = "Linux" ]; then
                    checkinstall -D --pkgname=qemu-$qemu_version --nodoc --showinstall=no --default
                elif [ "$OS" = "Darwin" ]; then
                    make -j"$(getconf _NPROCESSORS_ONLN)" install
                fi
                # hack for libvirt/virt-manager
                if [ ! -f /usr/bin/qemu-system-x86_64-spice ]; then
                    ln -s /usr/bin/qemu-system-x86_64 /usr/bin/qemu-system-x86_64-spice
                fi
                if [ ! -f /usr/bin/kvm-spice ]; then
                    ln -s /usr/bin/qemu-system-x86_64 /usr/bin/kvm-spice
                fi
                if [ ! -f /usr/bin/kvm ]; then
                    ln -s /usr/bin/qemu-system-x86_64 /usr/bin/kvm
                fi
                if  [ $? -eq 0 ]; then
                    echo '[+] Patched, compiled and installed'
                else
                    echo '[-] Install failed'
                fi
                groupadd tss
                useradd -g tss tss
            else
                echo '[-] Compilling failed'
            fi
        else
            echo '[-] Check previous output'
            exit
        fi

    #else
    #    echo '[-] Download QEMU source was not possible'
    #fi
    if [ "$OS" = "linux" ]; then
        dpkg --get-selections | grep "qemu" | xargs apt-mark hold
        dpkg --get-selections | grep "libvirt" | xargs apt-mark hold
        # apt-mark unhold qemu
    fi

}

function seabios_func() {
    cd /tmp || return
    fail=0
    echo '[+] Installing SeaBios dependencies'
    apt-get install git iasl -y
    if [ -d seabios ]; then
        rm -r seabios
    fi
    if git clone https://github.com/coreboot/seabios.git; then
        cd seabios || return
        if declare -f -F "replace_seabios_clues"; then
            replace_seabios_clues
        else
            replace_seabios_clues_public
        fi
        # make help
        # make menuconfig -> BIOS tables -> disable Include default ACPI DSDT
        # get rid of this hack
        make -j "$(getconf _NPROCESSORS_ONLN)" 2>/dev/null
        sed -i 's/CONFIG_ACPI_DSDT=y/CONFIG_ACPI_DSDT=n/g' .config
        sed -i 's/CONFIG_XEN=y/CONFIG_XEN=n/g' .config
        if make -j "$(getconf _NPROCESSORS_ONLN)"; then
            echo '[+] Replacing old bios.bin to new out/bios.bin'
            bios=0
            FILES=(
                "/usr/share/qemu/bios.bin"
                "/usr/share/qemu/bios-256k.bin"
            )
            for file in "${FILES[@]}"; do
                cp -vf out/bios.bin "$file"
                bios=1
            done
            if [ $bios -eq 1 ]; then
                echo '[+] Patched bios.bin placed correctly'
            else
                echo '[-] Bios patching failed'
            fi
        else
            echo '[-] Bios compilation failed'
        fi
        cd - || return
    else
        echo '[-] Check if git installed or network connection is OK'
    fi
}

function issues(){
cat << EndOfHelp
### Links:
    * https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/virtualization_deployment_and_administration_guide/sect-troubleshooting-common_libvirt_errors_and_troubleshooting

### Errors and Solutions
    * Error:
        required by /usr/lib/libvirt/storage-file/libvirt_storage_file_fs.so
    * Solution:
        systemctl daemon-reload
        systemctl restart libvirtd libvirt-guests.service

    * Error:
        /libvirt.so.0: version LIBVIRT_PRIVATE_x.x.0' not found (required by /usr/sbin/libvirtd)
    * Solutions:
        1. apt-get purge libvirt0 libvirt-bin
        2. reboot
        3. $0 libvirt

        Can be extra help, but normally solved with first3 steps
        1. ldd /usr/sbin/libvirtd
        2. ls -lah /usr/lib/libvirt*
            * Make sure what all symlinks pointing to last version

    * Error:
        libvirt: Polkit error : authentication unavailable: no polkit agent available to authenticate action 'org.libvirt.unix.manage'
    * Solutions:
        1.
            sed -i 's/#unix_sock_group/unix_sock_group/g' /etc/libvirt/libvirtd.conf
            sed -i 's/#unix_sock_ro_perms = "0777"/unix_sock_ro_perms = "0770"/g' /etc/libvirt/libvirtd.conf
            sed -i 's/#unix_sock_rw_perms = "0770"/unix_sock_rw_perms = "0770"/g' /etc/libvirt/libvirtd.conf
            sed -i 's/#auth_unix_ro = "none"/auth_unix_ro = "none"/g' /etc/libvirt/libvirtd.conf
            sed -i 's/#auth_unix_rw = "none"/auth_unix_rw = "none"/g' /etc/libvirt/libvirtd.conf
        2. Add ssh key to $HOME/.ssh/authorized_keys
            virt-manager -c "qemu+ssh://user@host/system?socket=/var/run/libvirt/libvirt-sock"
    * Slow HDD/Snapshot taking performance?
        Modify
            <driver name='qemu' type='qcow2'/>
        To
            <driver name='qemu' type='qcow2' cache='none' io='native'/>
    * Error:
        error : virPidFileAcquirePath:422 : Failed to acquire pid file '/var/run/libvirtd.pid': Resource temporarily unavailable
    * Solution
        ps aux | grep libvirtd
    * Error:
        Failed to connect socket to '/var/run/libvirt/libvirt-sock': Permission denied
    * Solution:
        * usermod -G libvirt -a username
        * log out and log in

    # Fixes from http://ask.xmodulo.com/compile-virt-manager-debian-ubuntu.html
    1. ImportError: No module named libvirt
    $ $0 libvirt

    2. ImportError: No module named libxml2
    $ apt-get install python-libxml2 python3-libxml2

    3. ImportError: No module named requests
    $ apt-get install python-requests

    4. Error launching details: Namespace GtkVnc not available
    $ $0 libvirt

    5. Error launching details: Namespace SpiceClientGtk not available
    $ apt-get install gir1.2-spice-client-gtk-3.0

    6. ValueError: Namespace LibvirtGLib not available
    $ $0 libvirt

    7. ValueError: Namespace Libosinfo not available
    $ apt-get install libosinfo-1.0

    8. ImportError: No module named ipaddr
    $ apt-get install python-ipaddr

    9. Namespace Gtk not available: Could not open display: localhost:10.0
    $ apt-get install libgtk-3-dev

    10. ImportError: cannot import name Vte
    $ apt-get install gir1.2-vte-2.90

EndOfHelp
}

function install_WebVirtCloud(){
    sudo apt-get -y install git virtualenv python-virtualenv python-dev python-lxml libvirt-dev zlib1g-dev libxslt1-dev nginx supervisor libsasl2-modules gcc pkg-config python-guestfs
    git clone https://github.com/retspen/webvirtcloud
    cd webvirtcloud
    cp webvirtcloud/settings.py.template webvirtcloud/settings.py
    # now put secret key to webvirtcloud/settings.py
    sudo cp conf/supervisor/webvirtcloud.conf /etc/supervisor/conf.d
    sudo cp conf/nginx/webvirtcloud.conf /etc/nginx/conf.d
    cd ..
    sudo mv webvirtcloud /srv
    sudo chown -R www-data:www-data /srv/webvirtcloud
    cd /srv/webvirtcloud
    virtualenv venv
    source venv/bin/activate
    pip install -r conf/requirements.txt
    python manage.py migrate
    sudo chown -R www-data:www-data /srv/webvirtcloud
    sudo rm /etc/nginx/sites-enabled/default
    sudo service nginx restart
    sudo service supervisor restart
}

function cloning() {
    if [ $# -lt 5 ]; then
        echo '[-] You must provide <VM_NAME> <path_to_hdd> <start_from_number> <#vm_to_create> <path_where_to_store> <network_base>'
        exit 1
    fi
    for i in $(seq "$3" "$4"); do
        worked=1
        # bad macaddress can be generated
        while [ $worked -eq 1 ]; do
            macaddr=$(hexdump -n 6 -ve '1/1 "%.2x "' /dev/random | awk -v a="2,6,a,e" -v r="$RANDOM" 'BEGIN{srand(r);}NR==1{split(a,b,",");r=int(rand()*4+1);printf "%s%s:%s:%s:%s:%s:%s\n",substr($1,0,1),b[r],$2,$3,$4,$5,$6}') 2>/dev/null
            #virt-clone --print-xml -n $1_$i -o $1 -m "$macaddr"
            if [ ! -f "${5}/${1}_${i}.qcow2" ]; then
                #Linked snapshots are disabled due to performance problems
                #qemu-img create -f qcow2 -b "$2" "$5/$1_$i.qcow2"
                #rsync -ahW --no-compress --progress "$2" "$5/$1_$i.qcow2"
                echo "Creating $5/$1_$i.qcow2"
                cp "$2" "$5/$1_$i.qcow2"
            fi
            #2>/dev/null
            if virt-clone --print-xml -n "$1_$i" -o "$1" -m "$macaddr" |sed "s|<driver name=\"qemu\" type=\"qcow2\" cache=\"none\" io=\"native\"/>|<driver name=\"qemu\" type=\"qcow2\" cache=\"none\" io=\"native\"/>\\n      <source file=\"${5}/${1}_${i}.qcow2\"/>|g" > "$5/$1_$i.xml"; then
                sed -i "s|<domain type='kvm'>|<domain type='kvm' xmlns:qemu='http://libvirt.org/schemas/domain/qemu/1.0'>|g" "$5/$1_$i.xml"
                virsh define "$5/$1_$i.xml"
                worked=0
            fi
        done
        echo "<host mac='$macaddr' name='$1_$i' ip='$6.$(($i+1))'/>"
    done

    echo "[+] Enjoy"

}

# Doesn't work ${$1,,}
COMMAND=$(echo "$1"|tr "[A-Z]" "[a-z]")

case $COMMAND in
    '-h')
        usage
        exit 0;;
    'issues')
        issues
        exit 0;;
esac

#if ([ "$COMMAND" = "all" ] || [ "$COMMAND" = "libvirt" ]) && [ $# -eq 2 ]; then
#    if [ id -u "$2" ]; then
#        username="$2"
#    else
#        echo "[-] username $2 doesn't exist"
#        exit 1
#    fi
#fi

#check if start with root
if [ "$EUID" -ne 0 ]; then
   echo 'This script must be run as root'
   exit 1
fi

OS="$(uname -s)"
#add-apt-repository universe
#apt-get update && apt-get upgrade
#make

case "$COMMAND" in
'all')
    apt-get install language-pack-UTF-8
    qemu_func
    seabios_func
    if [ "$OS" = "Linux" ]; then
        install_kvm_linux_apt
        install_libguestfs
        # check if all features enabled
        virt-host-validate
        systemctl daemon-reload
        systemctl restart libvirtd libvirt-guests.service
        _enable_tcp_bbr
    elif [ "$OS" = "Darwin" ]; then
        install_haxm_mac
    fi
    ;;
'qemu')
    qemu_func;;
'seabios')
    seabios_func;;
'kvm')
    install_kvm_linux_apt;;
'haxm')
    install_haxm_mac;;
'libguestfs')
    install_libguestfs;;
'tcp_bbr')
    _enable_tcp_bbr;;
'replace_qemu')
    if declare -f -F "replace_qemu_clues"; then
        replace_qemu_clues
    else
        replace_qemu_clues_public
    fi
    ;;
'libvirt')
    install_libvirt;;
'clone')
    cloning "$2" "$3" "$4" "$5" "$6" "$7";;
'noip')
    if [ "$OS" = "Linux" ]; then
        cd /tmp
        wget http://www.no-ip.com/client/linux/noip-duc-linux.tar.gz
        tar xf noip-duc-linux.tar.gz
        rm noip-duc-linux.tar.gz
        cd "noip-*"
        make install
        crontab -l | { cat; echo "@reboot sleep 10 && /usr/local/bin/noip2 -c /usr/local/etc/no-ip2.conf"; } | crontab -
    elif [ "$OS" = "Darwin" ]; then
        _check_brew
        brew cask install no-ip-duc
    fi
    ;;
'replace_seabios')
    if [ ! -d "$2" ]; then
        echo "[-] Pass the path to SeaBios folder"
        exit 1
    fi
    cd "$2" || exit 1
    if declare -f -F "replace_seabios_clues"; then
        replace_seabios_clues
    else
        replace_seabios_clues_public
    fi
    cd - || exit 0
    ;;
'changelog')
    changelog;;
'webvirtmgr')
    install_WebVirtCloud;;
*)
    usage;;
esac
