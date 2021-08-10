ARG SR_LINUX_RELEASE
ARG SR_BASEIMG
FROM $SR_BASEIMG:$SR_LINUX_RELEASE
# FROM registry.srlinux.dev/pub/srlinux:$SR_LINUX_RELEASE

# Install pyGNMI to /usr/local/lib[64]/python3.6/site-packages
RUN sudo yum install -y python3-pip gcc-c++ && \
    sudo python3 -m pip install pip --upgrade && \
    sudo python3 -m pip install pygnmi

# --chown=srlinux:srlinux
RUN sudo mkdir -p /etc/opt/srlinux/appmgr/
COPY ./appmgr/ /etc/opt/srlinux/appmgr

# Using a build arg to set the release tag, set a default for running docker build manually
ARG SRL_AUTO_CONFIG_RELEASE="[custom build]"
ENV SRL_AUTO_CONFIG_RELEASE=$SRL_AUTO_CONFIG_RELEASE
