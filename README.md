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

# The above creates an ACL entry under /acl cpm-filter ipv4-filter

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

# The above creates an ACL entry under /acl cpm-filter ipv6-filter

enter candidate
exit
delete neighbor 2001::1.2.3.4
commit now
```

To look at logs:
```
docker exec clab-bgp-acl-lab-spine1 cat /var/log/srlinux/stdout/bgp_acl_agent.log
```

## Implementation notes
The code registers with the SR Linux NDK to allow for (simple) configuration of the base sequence number of dynamically created ACL entries.
In parallel, it connects through gNMI to the local system using a unix socket (assuming default username/password, hardcoded).

The gNMI subscription is targeted at /network-instance[name=\*]/protocols/bgp/neighbor[peer-address=\*], which receives more events than strictly needed.
Events are filtered and only the base event is used to create an ACL entry. Similarly, 'delete' removes the ACL entry

ACL entries are created dynamically, by looking up existing entries and creating a new entry using the next available sequence number (starting from configured base).
It is assumed a 'drop all' entry exists at sequence number 65535

## Open issues
* There is a (configurable) connection rate limit on the gNMI interface; a large configuration with many existing BGP peers may exceed it during startup with the current approach of opening a new connection for each request

