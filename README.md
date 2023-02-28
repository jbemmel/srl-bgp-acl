# srl-bgp-acl
SR Linux agent to auto-create ACLs in response to BGP peers being added/removed

# Prerequisites
* make
* [Containerlab](https://containerlab.srlinux.dev/)

The agent connects to the NDK using a local Unix socket, which must be enabled in the configuration.
This is now added/checked as a condition in the Yang model.

# Setup
```
make build
sudo containerlab deploy -t ./srl-node.lab
```

# Test
1. Login to CLI (password: NokiaSrl1!)
```
ssh admin@clab-bgp-acl-lab-spine1
```

2. Enable the agent (requires Unix gNMI socket). Note that BGP context must exist before agent starts
```
enter candidate
/system gnmi-server unix-socket admin-state enable

# Make sure bgp context exists
/network-instance default protocols bgp
router-id 1.2.3.4
autonomous-system 12345

bgp-acl-agent acl-sequence-start 1000
commit stay
```

3. Copy & paste following CLI snippet (or part of it)
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
info /acl cpm-filter ipv4-filter entry 1000

enter candidate
exit
delete neighbor 1.2.3.4
commit now
```

Add 2 neighbors, delete both in the same commit:
```
enter candidate
/network-instance default protocols bgp
group test
exit
neighbor 1.2.3.4
peer-group test
admin-state enable
exit
neighbor 5.6.7.8
peer-group test
admin-state enable
exit
commit now

info /acl cpm-filter ipv4-filter

enter candidate
delete neighbor 1.2.3.4
delete neighbor 5.6.7.8
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
info /acl cpm-filter ipv6-filter entry 1000

enter candidate
exit
delete neighbor 2001::1.2.3.4
commit now
```

To look at logs:
```
docker exec clab-bgp-acl-lab-spine1 cat /var/log/srlinux/stdout/bgp_acl_agent.log
```

# .rpm package
A .rpm package was added to simplify installation onto physical nodes:

To build an .rpm:
```
make rpm
```

To install the .rpm in a bash shell on a node:
```
yum localinstall bgp-acl-agent-1.0.0.x86_64.rpm
```
Or, for nodes without Internet access:
```
rpm -ivh bgp-acl-agent-1.0.0.x86_64.rpm
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
