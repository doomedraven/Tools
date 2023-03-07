# Dead code - keeping just in case a copy
# use docker or another VM for sparsify VMs
function install_libguestfs() {
    # https://libguestfs.org/guestfs-building.1.html
    cd /opt || return
    echo "[+] Check for previous version of LibGuestFS"
    sudo dpkg --purge --force-all "libguestfs-*" 2>/dev/null

    # deprecated
    wget -O- https://packages.erlang-solutions.com/ubuntu/erlang_solutions.asc | sudo apt-key add -
    sudo add-apt-repository -y "deb https://packages.erlang-solutions.com/ubuntu $(lsb_release -sc) contrib"
    sudo aptitude install -f default-jdk parted libyara3 erlang-dev gperf flex bison libaugeas-dev libhivex-dev supermin ocaml-nox libhivex-ocaml genisoimage libhivex-ocaml-dev libmagic-dev libjansson-dev gnulib jq ocaml-findlib opam -y 2>/dev/null
    sudo apt update
    sudo aptitude install -f erlang -y

    if [ ! -d libguestfs ]; then
        # ToDo move to latest release not latest code
        #_info=$(curl -H "Accept: application/vnd.github+json" -s https://api.github.com/repos/libguestfs/libguestfs/tags)
        #_version=$(echo $_info |jq .[0].name|sed "s/\"//g")
        #_repo_url=$(echo $_info |jq ".[0].zipball_url" | sed "s/\"//g")
        #wget -q $_repo_url
        #unzip $_version
        git clone --recursive https://github.com/libguestfs/libguestfs
    fi


    HIVEX_VERSION=1.3.23
    # install hivex
    wget https://github.com/libguestfs/hivex/archive/refs/tags/v${HIVEX_VERSION}.zip
    unzip v${HIVEX_VERSION}
    cd hivex-${HIVEX_VERSION}
    autoreconf -i
    ./generator/generator.ml
    ./configure
    make -j"$(nproc)"
    # make check
    cd .. || return

    cd libguestfs || return
    # cd $(ls | grep "libguestfs-libguestfs*") || return
    git submodule update --init
    autoreconf -i
    eval $(opam env)
    opam init
    opam install augeas -y
    eval $(opam env)
    OCAMLPATH=$HOME/.opam/default/lib/ocaml::/usr/lib/ocaml ./configure CFLAGS=-fPIC --disable-ocaml --disable-perl --disable-python --disable-ruby --disable-haskell --disable-php --disable-erlang --disable-lua --disable-golang --disable-gobject
    OCAMLPATH=$HOME/.opam/default/lib/ocaml::/usr/lib/ocaml:/opt/hivex-{HIVEX_VERSION} make clean -j"$(nproc)"

    # Install virt tools that are in a diff repo since LIBGUESTFS 1.46 split
    # More Info: https://listman.redhat.com/archives/libguestfs/2021-September/msg00153.html
    cd /opt || return
    if [ ! -d guestfs-tools ]; then
      git clone --recursive https://github.com/rwmjones/guestfs-tools.git
    fi
    cd guestfs-tools || return
    # Following tips to compile the guestfs-tools as depicted in https://www.mail-archive.com/libguestfs@redhat.com/msg22408.html
    git config --global --add safe.directory /opt/guestfs-tools
    git submodule update --init --force
    autoreconf -i
    ../libguestfs/run ./configure CFLAGS=-fPIC
    ../libguestfs/run make -j"$(nproc)"

    echo "[+] /opt/libguestfs/run --help"
    echo "[+] /opt/libguestfs/run /opt/guestfs-tools/sparsify/virt-sparsify -h"
}
