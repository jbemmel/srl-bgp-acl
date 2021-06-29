# srl-bgp-acl
SR Linux agent to auto-create ACLs in response to BGP peers being added/removed

# Prerequisites
* make
* [Containerlab](https://containerlab.srlinux.dev/)

# Setup
```
make build
sudo containerlab deploy -t ./srl-node.lab
```

# Test
1. Login to CLI
```
ssh admin@clab-bgp-acl-lab-spine1
```

2. Copy & paste following CLI snippet (or part of it)
```
enter candidate
/network-instance default protocols bgp
group test
exit
neighbor 1.2.3.4
peer-group test
admin-state enable
commit now
enter candidate
exit
delete neighbor 1.2.3.4
commit now
```

For IPv6:
```
enter candidate 
/network-instance default protocols bgp
neighbor 2001::1.2.3.4
peer-group test
admin-state enable
commit now
enter candidate
exit
delete neighbor 2001::1.2.3.4
commit now
```

To look at logs:
```
docker exec clab-bgp-acl-lab-spine1 cat /var/log/srlinux/stdout/bgp_acl_agent.log
```
