#!/usr/bin/env python
# coding=utf-8

import grpc
import datetime
import sys
import logging
import socket
import os
from ipaddress import ip_network, ip_address, IPv4Address
import json
import signal
import traceback

import sdk_service_pb2
import sdk_service_pb2_grpc
import config_service_pb2

# from nsenter import Namespace
from pygnmi.client import gNMIclient, telemetryParser

from logging.handlers import RotatingFileHandler

############################################################
## Agent will start with this name
############################################################
agent_name='bgp_acl_agent'

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
def Handle_Notification(obj, state):
    if obj.HasField('config') and obj.config.key.js_path != ".commit.end":
        logging.info(f"GOT CONFIG :: {obj.config.key.js_path}")
        if "bgp_acl_agent" in obj.config.key.js_path:
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
                    state.acl_seq[4] = state.acl_seq[6] = data['acl_sequence_start']['value']
                    logging.info(f"Got init sequence :: {state.acl_seq}")

                return 'acl_sequence_start' in data

    else:
        logging.info(f"Unexpected notification : {obj}")

    return False


##################################################################################################
## This functions get the app_id from idb for a given app_name
##################################################################################################
def get_app_id(app_name):
    logging.info(f'Metadata {metadata} ')
    appId_req = sdk_service_pb2.AppIdRequest(name=app_name)
    app_id_response=stub.GetAppId(request=appId_req, metadata=metadata)
    logging.info(f'app_id_response {app_id_response.status} {app_id_response.id} ')
    return app_id_response.id

def Gnmi_subscribe_bgp_changes(state):
    subscribe = {
            'subscription': [
                {
                    # 'path': '/srl_nokia-network-instance:network-instance[name=*]/protocols/srl_nokia-bgp:bgp/neighbor[peer-address=*]/admin-state',
                    # Possible to subscribe without '/admin-state', but then too many events
                    # Like this, no 'delete' is received when the neighbor is deleted
                    # Also, 'enable' event is followed by 'disable' - broken
                    # 'path': '/network-instance[name=*]/protocols/bgp/neighbor[peer-address=*]/admin-state',
                    # This leads to too many events, hitting the max 60/minute gNMI limit
                    # 'path': '/network-instance[name=*]/protocols/bgp/neighbor[peer-address=*]',
                    'path': '/network-instance[name=*]/protocols/bgp/neighbor[peer-address=*]/peer-group',
                    'mode': 'on_change',
                    # 'heartbeat_interval': 10 * 1000000000 # ns between, i.e. 10s
                    # Mode 'sample' results in polling
                    # 'mode': 'sample',
                    # 'sample_interval': 10 * 1000000000 # ns between samples, i.e. 10s
                }
            ],
            'use_aliases': False,
            'mode': 'stream',
            'encoding': 'json'
        }
    # _bgp = re.compile( '^network-instance\[name=(.*)\]/protocols/bgp/neighbor\[peer-address=(.*)\]/admin-state$' )

    # with Namespace('/var/run/netns/srbase-mgmt', 'net'):
    with gNMIclient(target=('unix:///opt/srlinux/var/run/sr_gnmi_server',57400),
                            username="admin",password="admin",
                            insecure=True) as c:
      telemetry_stream = c.subscribe(subscribe=subscribe)
      for m in telemetry_stream:
        try:
          parsed = telemetryParser(m) # XXX not strictly needed to parse this
          logging.info(f"GOT BGP change event :: {m} parsed={parsed}")

          if m.HasField('update'):
              root = m.update.update
          elif m.HasField('sync_response'):
              root = []
          elif m.HasField('delete'): # Triggers error?
              root = m.delete.update
          else:
              root = []

          # XXX gets update.delete for deletes, but not when subscribing to /admin-state
          for u in root:
             if u.path and u.path.elem:
                 for e in u.path.elem:
                    logging.info(f"Processing path elem {e} name='{e.name}'")
                    if e.name == "neighbor":
                       for n,v in e.key.items():
                           logging.info(f"n={n} v={v}")
                           if n=="peer-address":
                              _peer_ip = v
                              logging.info(f"neighbor {_peer_ip}")
                              # if u.val.string_val == "enable":
                              if m.HasField('update'):
                                 Add_ACL(c,state,_peer_ip)
                              else:
                                 Remove_ACL(c,_peer_ip)
                       break

        except Exception as e:
          traceback_str = ''.join(traceback.format_tb(e.__traceback__))
          logging.error(f'Exception caught in gNMI :: {e} stack:{traceback_str}')
    logging.info("Leaving BGP event loop")

def checkIP(ip):
    try:
        return 4 if type(ip_address(ip)) is IPv4Address else 6
    except ValueError:
        return None

def Add_ACL(gnmi,state,peer_ip):
    seq = Find_ACL_entry(gnmi,peer_ip)
    if seq is None:
        v = checkIP(peer_ip)

        seq = state.acl_seq[v]
        state.acl_seq[v] += 1
        acl_entry = {
          "match": {
            ("protocol" if v==4 else "next-header"): "tcp",
            "source-ip": { "prefix": peer_ip + '/' + ('32' if v==4 else '128') },
            "destination-port": { "operator": "eq", "value": 179 }
          },
          "action": { "accept": { } }
        }
        path = f'/acl/cpm-filter/ipv{v}-filter/entry[sequence-id={seq}]'
        logging.info(f"Update: {path}={acl_entry}")
        gnmi.set( encoding='json_ietf', update=[(path,acl_entry)] )

def Remove_ACL(gnmi,peer_ip):
   seq = Find_ACL_entry(gnmi,peer_ip)
   if seq is not None:
       logging.info(f"Deleting ACL entry :: {seq}")
       v = checkIP(peer_ip)
       path = f'/acl/cpm-filter/ipv{v}-filter/entry[sequence-id={seq}]'
       gnmi.set( encoding='json_ietf', delete=[path] )

#
# Because it is possible that ACL entries get saved to 'startup', the agent may
# not have a full map of sequence number to peer_ip. Therefore, we perform a
# lookup based on IP address each time
# Since 'prefix' is not a key, we have to loop through all entries
#
def Find_ACL_entry(gnmi,peer_ip):

   # path = '/acl/cpm-filter/ipv4-filter/entry[sequence-id=*]/match/source-ip/prefix'
   v = checkIP(peer_ip)
   path = f'/acl/cpm-filter/ipv{v}-filter/entry/match/source-ip/prefix'
   acl_entries = gnmi.get( encoding='json_ietf', path=[path] )
   logging.info(f"GOT Notification :: {acl_entries}")
   searched = peer_ip + '/' + ('32' if v==4 else '128')
   for e in acl_entries['notification']:
     try:
      if 'update' in e:
        logging.info(f"GOT Update :: {e['update']}")
        for u in e['update']:
            for j in u['val']['entry']:
               logging.info(f"GOT ACL entry :: {j}")
               prefix = j['match']['source-ip']['prefix']
               if prefix==searched:
                   logging.info(f"Found matching entry :: {j}")
                   return j['sequence-id']
     except Exception as e:
        logging.error(f'Exception caught in Find_ACL_entry :: {e}')
   return None

class State(object):
    def __init__(self):
        self.acl_seq = { 4: 1000, 6: 1000 } # Starting index, todo configurable

    def __str__(self):
        return str(self.__class__) + ": " + str(self.__dict__)

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

    app_id = get_app_id(agent_name)
    if not app_id:
        logging.error(f'idb does not have the appId for {agent_name} : {app_id}')
        sys.exit(-1)
    else:
        logging.info(f'Got appId {app_id} for {agent_name}')

    request=sdk_service_pb2.NotificationRegisterRequest(op=sdk_service_pb2.NotificationRegisterRequest.Create)
    create_subscription_response = stub.NotificationRegister(request=request, metadata=metadata)
    stream_id = create_subscription_response.stream_id
    logging.info(f"Create subscription response received. stream_id : {stream_id}")

    state = State()

    Subscribe_Notifications(stream_id)

    stream_request = sdk_service_pb2.NotificationStreamRequest(stream_id=stream_id)
    stream_response = sub_stub.NotificationStream(stream_request, metadata=metadata)

    Gnmi_subscribe_bgp_changes(state)

    try:
        for r in stream_response:
            logging.info(f"Count :: {count}  NOTIFICATION:: \n{r.notification}")
            for obj in r.notification:
                if obj.HasField('config') and obj.config.key.js_path == ".commit.end":
                    logging.info('TO DO -commit.end config')
                else:
                    Handle_Notification(obj, state)

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
    logging.info("Caught signal :: {}\n will unregister fib_agent".format(signum))
    try:
        response=stub.AgentUnRegister(request=sdk_service_pb2.AgentRegistrationRequest(), metadata=metadata)
        logging.error('try: Unregister response:: {}'.format(response))
        sys.exit()
    except grpc._channel._Rendezvous as err:
        logging.info('GOING TO EXIT NOW: {}'.format(err))
        sys.exit()

##################################################################################################
## Main from where the Agent starts
## Log file is written to: /var/log/srlinux/stdout/<dutName>_fibagent.log
## Signals handled for graceful exit: SIGTERM
##################################################################################################
if __name__ == '__main__':
    # hostname = socket.gethostname()
    stdout_dir = '/var/log/srlinux/stdout' # PyTEnv.SRL_STDOUT_DIR
    signal.signal(signal.SIGTERM, Exit_Gracefully)
    if not os.path.exists(stdout_dir):
        os.makedirs(stdout_dir, exist_ok=True)
    log_filename = '{}/bgp-acl-agent.log'.format(stdout_dir)
    logging.basicConfig(filename=log_filename, filemode='a',\
                        format='%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s',\
                        datefmt='%H:%M:%S', level=logging.INFO)
    handler = RotatingFileHandler(log_filename, maxBytes=3000000,backupCount=5)
    logging.getLogger().addHandler(handler)
    logging.info("START TIME :: {}".format(datetime.datetime.now()))
    if Run():
        logging.info('Agent unregistered')
    else:
        logging.info('Should not happen')
