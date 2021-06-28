FROM registry.srlinux.dev/pub/srlinux:latest

RUN printf '%s\n' \
  '#!/bin/bash' \
  '' \
  'mkdir -p /etc/opt/srlinux/appmgr && cp /home/appmgr/* /etc/opt/srlinux/appmgr/' \
  'exit $?' \
  \
> /tmp/42.sh && sudo mv /tmp/42.sh /opt/srlinux/bin/bootscript/42_sr_copy_custom_appmgr.sh && \
  sudo chmod a+x /opt/srlinux/bin/bootscript/42_sr_copy_custom_appmgr.sh

# Install pyGNMI and Jinja2 to /usr/local/lib[64]/python3.6/site-packages
RUN sudo yum install -y python3-pip gcc-c++ && \
    sudo python3 -m pip install pip --upgrade && \
    sudo python3 -m pip install pygnmi

# --chown=srlinux:srlinux
# COPY ./appmgr/ /etc/opt/srlinux/appmgr/ # doesn't stick
COPY ./appmgr/ /home/appmgr

# Using a build arg to set the release tag, set a default for running docker build manually
ARG SRL_AUTO_CONFIG_RELEASE="[custom build]"
ENV SRL_AUTO_CONFIG_RELEASE=$SRL_AUTO_CONFIG_RELEASE
