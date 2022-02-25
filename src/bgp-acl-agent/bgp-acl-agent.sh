#!/bin/bash
###########################################################################
# Description:
#     This script will launch the python script of auto_config_agent
#     (forwarding any arguments passed to this script).
#
# Copyright (c) 2018-2021 Nokia
###########################################################################


_term (){
    echo "Caugth signal SIGTERM !! "
    kill -TERM "$child" 2>/dev/null
}

function main()
{
    trap _term SIGTERM
    # local virtual_env="/opt/srlinux/python/virtual-env/bin/activate"
    local virtual_env="/opt/demo-agents/bgp-acl-agent/.venv/bin/activate"
    local main_module="/opt/demo-agents/bgp-acl-agent/bgp-acl-agent.py"

    # source the virtual-environment, which is used to ensure the correct python packages are installed,
    # and the correct python version is used
    source "${virtual_env}"

    # Include local paths where custom packages are installed
    VENV_LIB="/opt/demo-agents/bgp-acl-agent/.venv/lib/python3.6/site-packages"
    # P2="/usr/local/lib64/python3.6/site-packages"
    # NDK="/opt/rh/rh-python36/root/usr/lib/python3.6/site-packages/sdk_protos"
    # since 21.6
    NDK="/usr/lib/python3.6/site-packages/sdk_protos"
    export PYTHONPATH="$NDK:$VENV_LIB:$PYTHONPATH"

    # [[ ! -f /var/run/netns/srbase-mgmt ]] && sleep 10
    # /usr/sbin/ip netns exec srbase-mgmt python3 ${main_module} &
    # Now using Unix socket to connect locally
    python3 ${main_module} &

    child=$!
    wait "$child"

}

main "$@"
