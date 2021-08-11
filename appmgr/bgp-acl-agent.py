#!/usr/bin/env python
# coding=utf-8

import grpc
from datetime import datetime
import sys
import logging
import socket
import os
from ipaddress import ip_network, ip_address, IPv4Address
import json
import signal
import traceback
import re
from concurrent.futures import ThreadPoolExecutor

import sdk_service_pb2
import sdk_service_pb2_grpc
import config_service_pb2

# To report state back
import telemetry_service_pb2
import telemetry_service_pb2_grpc

from pygnmi.client import gNMIclient, telemetryParser
from logging.handlers import RotatingFileHandler

############################################################
## Agent will start with this name
############################################################
agent_name='bgp_acl_agent'

acl_sequence_start=1000 # Default ACL sequence number base, can be configured
acl_count=0             # Number of ACL entries created/managed

############################################################
## Open a GRPC channel to connect to sdk_mgr on the dut
## sdk_mgr will be listening on 50053
############################################################
channel = grpc.insecure_channel('unix:///opt/srlinux/var/run/sr_sdk_service_manager:50053')
# channel = grpc.insecure_channel('127.0.0.1:50053')
metadata = [('agent_name', agent_name)]
stub = sdk_service_pb2_grpc.SdkMgrServiceStub(channel)

############################################################
## Subscribe to required event
## This proc handles subscription of: Interface, LLDP,
##                      Route, Network Instance, Config
############################################################
def Subscribe(stream_id, option):
    op = sdk_service_pb2.NotificationRegisterRequest.AddSubscription
    if option == 'cfg':
        entry = config_service_pb2.ConfigSubscriptionRequest()
        entry.key.js_path = '.' + agent_name # filter out .commit.end notifications
        request = sdk_service_pb2.NotificationRegisterRequest(op=op, stream_id=stream_id, config=entry)

    subscription_response = stub.NotificationRegister(request=request, metadata=metadata)
    print('Status of subscription response for {}:: {}'.format(option, subscription_response.status))

############################################################
## Subscribe to all the events that Agent needs
############################################################
def Subscribe_Notifications(stream_id):
    '''
    Agent will receive notifications to what is subscribed here.
    '''
    if not stream_id:
        logging.info("Stream ID not sent.")
        return False

    # Subscribe to config changes, first
    Subscribe(stream_id, 'cfg')

##################################################################
## Proc to process the config Notifications received by auto_config_agent
## At present processing config from js_path = .fib-agent
##################################################################
def Handle_Notification(obj):
    if obj.HasField('config'):
        logging.info(f"GOT CONFIG :: {obj.config.key.js_path}")
        if obj.config.key.js_path == ".bgp_acl_agent":
            logging.info(f"Got config for agent, now will handle it :: \n{obj.config}\
                            Operation :: {obj.config.op}\nData :: {obj.config.data.json}")
            if obj.config.op == 2:
                logging.info(f"Delete bgp-acl-agent cli scenario")
                # if file_name != None:
                #    Update_Result(file_name, action='delete')
                response=stub.AgentUnRegister(request=sdk_service_pb2.AgentRegistrationRequest(), metadata=metadata)
                logging.info('Handle_Config: Unregister response:: {}'.format(response))
            else:
                json_acceptable_string = obj.config.data.json.replace("'", "\"")
                data = json.loads(json_acceptable_string)
                if 'acl_sequence_start' in data:
                    acl_sequence_start = data['acl_sequence_start']['value']
                    logging.info(f"Got init sequence :: {acl_sequence_start}")

                return 'acl_sequence_start' in data

    else:
        logging.info(f"Unexpected notification : {obj}")

    return False

def Gnmi_subscribe_bgp_changes():
    subscribe = {
            'subscription': [
                {
                    # 'path': '/srl_nokia-network-instance:network-instance[name=*]/protocols/srl_nokia-bgp:bgp/neighbor[peer-address=*]/admin-state',
                    # Possible to subscribe without '/admin-state', but then too many events
                    # Like this, no 'delete' is received when the neighbor is deleted
                    # Also, 'enable' event is followed by 'disable' - broken
                    # 'path': '/network-instance[name=*]/protocols/bgp/neighbor[peer-address=*]/admin-state',
                    # This leads to too many events, hitting the max 60/minute gNMI limit
                    # 10 events per CLI change to a bgp neighbor, many duplicates
                    # 'path': '/network-instance[name=*]/protocols/bgp/neighbor[peer-address=*]',
                    'path': '/network-instance[name=*]/protocols/bgp/neighbor[peer-address=*]',
                    'mode': 'on_change',
                    # 'heartbeat_interval': 10 * 1000000000 # ns between, i.e. 10s
                    # Mode 'sample' results in polling
                    # 'mode': 'sample',
                    # 'sample_interval': 10 * 1000000000 # ns between samples, i.e. 10s
                },
                {  # Also monitor dynamic-neighbors sections
                   'path': '/network-instance[name=*]/protocols/bgp/dynamic-neighbors/accept/match[prefix=*]',
                   'mode': 'on_change',
                }
            ],
            'use_aliases': False,
            'mode': 'stream',
            'encoding': 'json'
        }
    _bgp = re.compile( r'^network-instance\[name=([^]]*)\]/protocols/bgp/neighbor\[peer-address=([^]]*)\]/admin-state$' )
    _dyn = re.compile( r'^network-instance\[name=([^]]*)\]/protocols/bgp/dynamic-neighbors/accept/match[prefix=([^]]*)\]/peer-group$' )

    # with Namespace('/var/run/netns/srbase-mgmt', 'net'):
    with gNMIclient(target=('unix:///opt/srlinux/var/run/sr_gnmi_server',57400),
                            username="admin",password="admin",
                            insecure=True, debug=False) as c:
      telemetry_stream = c.subscribe(subscribe=subscribe)
      for m in telemetry_stream:
        try:
          if m.HasField('update'): # both update and delete events
              # Filter out only toplevel events
              parsed = telemetryParser(m)
              logging.info(f"gNMI change event :: {parsed}")
              update = parsed['update']
              if update['update']:
                 path = update['update'][0]['path']  # Only look at top level
                 neighbor = _bgp.match( path )
                 if neighbor:
                    ip_prefix = neighbor.groups()[1]
                    logging.info(f"Got neighbor change event :: {peer_ip}")
                 else:
                    dyn_group = _dyn.match( path )
                    if dyn_group:
                       ip_prefix = dyn_group.groups()[1] # prefix
                    else:
                      logging.info(f"Ignoring gNMI change event :: {path}")
                      continue

                 # No-op if already exists
                 Add_ACL(c,ip_prefix.split('/'))
              else: # pygnmi does not provide 'path' for delete events
                 handleDelete(c,m)

        except Exception as e:
          traceback_str = ''.join(traceback.format_tb(e.__traceback__))
          logging.error(f'Exception caught in gNMI :: {e} m={m} stack:{traceback_str}')
    logging.info("Leaving BGP event loop")

def handleDelete(gnmi,m):
    logging.info(f"handleDelete :: {m}")
    for e in m.update.delete:
       for p in e.elem:
         # TODO dynamic-neighbors
         if p.name == "neighbor":
           for n,v in p.key.items():
             logging.info(f"n={n} v={v}")
             if n=="peer-address":
                peer_ip = v
                Remove_ACL(gnmi,peer_ip)
                return # XXX could be multiple peers deleted in 1 go?

#
# Checks if this is an IPv4 or IPv6 address, and normalizes host prefixes
#
def checkIP( ip_prefix ):
    try:
        v = 4 if type(ip_address(ip)) is IPv4Address else 6
        if len(ip_prefix)==1:
           ip_prefix[1] = '32' if v==4 else '128'
        return v
    except ValueError:
        return None

def Add_Telemetry(js_path, dict):
    telemetry_stub = telemetry_service_pb2_grpc.SdkMgrTelemetryServiceStub(channel)
    telemetry_update_request = telemetry_service_pb2.TelemetryUpdateRequest()
    telemetry_info = telemetry_update_request.state.add()
    telemetry_info.key.js_path = js_path
    telemetry_info.data.json_content = json.dumps(dict)
    logging.info(f"Telemetry_Update_Request :: {telemetry_update_request}")
    telemetry_response = telemetry_stub.TelemetryAddOrUpdate(request=telemetry_update_request, metadata=metadata)
    logging.info(f"TelemetryAddOrUpdate response:{telemetry_response}")
    return telemetry_response

def Update_ACL_Counter(delta):
    global acl_count
    acl_count += delta
    _ts = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
    Add_Telemetry( ".bgp_acl_agent", { "acl_count"   : acl_count,
                                       "last_change" : _ts } )

def Add_ACL(gnmi,ip_prefix):
    seq, next_seq = Find_ACL_entry(gnmi,ip_prefix) # Also returns next available entry
    if seq is None:
        v = checkIP(ip_prefix)
        acl_entry = {
          "created-by-bgp-acl-agent" : datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
          "match": {
            ("protocol" if v==4 else "next-header"): "tcp",
            "source-ip": { "prefix": ip_prefix[0] + '/' + ip_prefix[1] },
            "destination-port": { "operator": "eq", "value": 179 }
          },
          "action": { "accept": { } },
        }
        path = f'/acl/cpm-filter/ipv{v}-filter/entry[sequence-id={next_seq}]'
        logging.info(f"Update: {path}={acl_entry}")
        gnmi.set( encoding='json_ietf', update=[(path,acl_entry)] )

        # Need to set state separately, not via gNMI. Uses underscores in path
        # Tried extending ACL entries, but system won't accept these updates
        # js_path = (f'.acl.cpm_filter.ipv{v}_filter.entry' +
        #            '{.sequence_id==' + str(next_seq) + '}.bgp_acl_agent_state')
        # js_path = '.bgp_acl_agent.entry{.ip=="'+peer_ip+'"}'
        # Add_Telemetry( js_path, { "sequence_id": next_seq } )
        Update_ACL_Counter( +1 )

def Remove_ACL(gnmi,peer_ip):
   seq, next_seq, v = Find_ACL_entry(gnmi,[peer_ip])
   if seq is not None:
       logging.info(f"Remove_ACL: Deleting ACL entry :: {seq}")
       path = f'/acl/cpm-filter/ipv{v}-filter/entry[sequence-id={seq}]'
       gnmi.set( encoding='json_ietf', delete=[path] )
       Update_ACL_Counter( -1 )
   else:
       logging.info(f"Remove_ACL: No entry found for peer_ip={peer_ip}")

#
# Because it is possible that ACL entries get saved to 'startup', the agent may
# not have a full map of sequence number to peer_ip. Therefore, we perform a
# lookup based on IP address each time
# Since 'prefix' is not a key, we have to loop through all entries with a prefix
#
def Find_ACL_entry(gnmi,ip_prefix):
   v = checkIP( ip_prefix )

   #
   # Can do it like this and add custom state, but then we cannot find the next
   # available sequence number we can use
   # path = f"/bgp-acl-agent/entry[ip={peer_ip}]"
   path = f'/acl/cpm-filter/ipv{v}-filter/entry/match/'
   # could add /source-ip/prefix but then we cannot check for dest-port

   # Could filter like this to reduce #entries, limits to max 999 entries
   # path = '/acl/cpm-filter/ipv4-filter/entry[sequence-id=1*]/match

   # Interestingly, datatype='config' is required to see custom config state
   # The default datatype='all' does not show it
   acl_entries = gnmi.get( encoding='json_ietf', path=[path] )
   logging.info(f"Find_ACL_entry({peer_ip}): GOT GET response :: {acl_entries}")
   searched = peer_ip + '/' + ('32' if v==4 else '128')
   next_seq = acl_sequence_start
   for e in acl_entries['notification']:
     try:
      if 'update' in e:
        logging.info(f"GOT Update :: {e['update']}")
        for u in e['update']:
            for j in u['val']['entry']:
               logging.info(f"Check ACL entry :: {j}")
               match = j['match']
               # Users could change acl_sequence_start
               if 'source-ip' in match: # and j['sequence-id'] >= acl_sequence_start:
                  src_ip = match['source-ip']
                  if 'prefix' in src_ip:
                     if (src_ip['prefix'] == searched):
                       logging.info(f"Find_ACL_entry: Found matching entry :: {j}")
                       # Perform extra sanity check
                       if ('destination-port' in match
                            and 'value' in match['destination-port']
                            and match['destination-port']['value'] == 179):
                           return (j['sequence-id'],None,v)
                       else:
                           logging.info( "Source IP match but not BGP port" )
                     if j['sequence-id']==next_seq:
                       logging.info( f"Increment next_seq (={next_seq})" )
                       next_seq += 1
               else:
                  logging.info( "No source-ip in entry" )
     except Exception as e:
        logging.error(f'Exception caught in Find_ACL_entry :: {e}')
   logging.info(f"Find_ACL_entry: no match for searched={searched} next_seq={next_seq}")
   return (None,next_seq,v)

##################################################################################################
## This is the main proc where all processing for auto_config_agent starts.
## Agent registration, notification registration, Subscrition to notifications.
## Waits on the subscribed Notifications and once any config is received, handles that config
## If there are critical errors, Unregisters the fib_agent gracefully.
##################################################################################################
def Run():
    sub_stub = sdk_service_pb2_grpc.SdkNotificationServiceStub(channel)

    response = stub.AgentRegister(request=sdk_service_pb2.AgentRegistrationRequest(), metadata=metadata)
    logging.info(f"Registration response : {response.status}")

    request=sdk_service_pb2.NotificationRegisterRequest(op=sdk_service_pb2.NotificationRegisterRequest.Create)
    create_subscription_response = stub.NotificationRegister(request=request, metadata=metadata)
    stream_id = create_subscription_response.stream_id
    logging.info(f"Create subscription response received. stream_id : {stream_id}")

    Subscribe_Notifications(stream_id)

    stream_request = sdk_service_pb2.NotificationStreamRequest(stream_id=stream_id)
    stream_response = sub_stub.NotificationStream(stream_request, metadata=metadata)

    # Gnmi_subscribe_bgp_changes()
    executor = ThreadPoolExecutor(max_workers=1)
    executor.submit(Gnmi_subscribe_bgp_changes)

    try:
        for r in stream_response:
            logging.info(f"NOTIFICATION:: \n{r.notification}")
            for obj in r.notification:
                Handle_Notification(obj)

    except grpc._channel._Rendezvous as err:
        logging.info(f'GOING TO EXIT NOW: {err}')

    except Exception as e:
        logging.error(f'Exception caught :: {e}')
        #if file_name != None:
        #    Update_Result(file_name, action='delete')
        try:
            response = stub.AgentUnRegister(request=sdk_service_pb2.AgentRegistrationRequest(), metadata=metadata)
            logging.error(f'Run try: Unregister response:: {response}')
        except grpc._channel._Rendezvous as err:
            logging.info(f'GOING TO EXIT NOW: {err}')
            sys.exit()
        return True
    sys.exit()
    return True
############################################################
## Gracefully handle SIGTERM signal
## When called, will unregister Agent and gracefully exit
############################################################
def Exit_Gracefully(signum, frame):
    logging.info("Caught signal :: {}\n will unregister bgp acl agent".format(signum))
    try:
        response=stub.AgentUnRegister(request=sdk_service_pb2.AgentRegistrationRequest(), metadata=metadata)
        logging.error('try: Unregister response:: {}'.format(response))
        sys.exit()
    except grpc._channel._Rendezvous as err:
        logging.info('GOING TO EXIT NOW: {}'.format(err))
        sys.exit()

##################################################################################################
## Main from where the Agent starts
## Log file is written to: /var/log/srlinux/stdout/bgp_acl_agent.log
## Signals handled for graceful exit: SIGTERM
##################################################################################################
if __name__ == '__main__':
    # hostname = socket.gethostname()
    stdout_dir = '/var/log/srlinux/stdout' # PyTEnv.SRL_STDOUT_DIR
    signal.signal(signal.SIGTERM, Exit_Gracefully)
    if not os.path.exists(stdout_dir):
        os.makedirs(stdout_dir, exist_ok=True)
    log_filename = f'{stdout_dir}/{agent_name}.log'
    logging.basicConfig(
      handlers=[RotatingFileHandler(log_filename, maxBytes=3000000,backupCount=5)],
      format='%(asctime)s,%(msecs)03d %(name)s %(levelname)s %(message)s',
      datefmt='%H:%M:%S', level=logging.INFO)
    logging.info("START TIME :: {}".format(datetime.now()))
    if Run():
        logging.info('Agent unregistered')
    else:
        logging.info('Should not happen')
