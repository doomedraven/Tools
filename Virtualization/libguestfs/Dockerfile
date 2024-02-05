# Based on https://anthony-f-tannous.medium.com/use-docker-and-libguestfs-tools-to-shrink-virtual-machine-disks-vmdks-cae0aae17da6
# https://lucascavalare.github.io/2020-03-15-AppArmor_Docker/

# DO NOT INSTALL Docker from SNAP, it will give problems with permissions on mounting folders, as readonly blablabla
# https://docs.docker.com/engine/install/ubuntu/

# sudo apt-get update
# sudo apt-get install ca-certificates curl
# sudo install -m 0755 -d /etc/apt/keyrings
# sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
# sudo chmod a+r /etc/apt/keyrings/docker.asc

# Add the repository to Apt sources:
# echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
# sudo apt-get update
# sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# To enable internet
# echo 'DOCKER_OPTS="--dns 8.8.8.8 --dns 8.8.4.4"' >> /etc/default/docker
# sudo docker build --network=host  -t guest-fs-tools .

# Running
# sudo docker run -it --rm --privileged -v /opt/VMs:/mnt/vm-disks guest-fs-tools
# docker exec -it $(docker container ls  | grep 'guest-fs-tools' | awk '{print $1}') sudo /usr/bin/virt-sparsify path_to_vm path_to_out_vm --tmp /mnt/vm-disks
# Might need another volume mount which contains more space
# last command inside docker might require sudo

FROM ubuntu:22.04
RUN echo "deb http://us.archive.ubuntu.com/ubuntu/ jammy universe" >> /etc/apt/sources.list && \
 apt-get update && apt-get install -y --no-install-recommends libguestfs-tools  software-properties-common sudo apt-utils linux-image-generic
RUN useradd -ms /bin/bash -d /home/docker docker && usermod -aG sudo docker && echo "docker ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
ENV HOME=/home/docker
USER docker

