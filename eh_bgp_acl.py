#
# Copyright(C) 2023 Nokia
#
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
# PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE
# FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#
# An Event Handler version of the BGP ACL creation logic:
# * Subscribe to changes in provisioned BGP peers
# * When a new peer is detected, provision a new ACL for its IP address
#
# Example config:
EXAMPLE_CONFIG = """
enter candidate
/system event-handler instance bgp_acls
admin-state enable
upython-script eh_bgp_acl.py
paths [
 "network-instance default protocols bgp neighbor * last-event"
]
options { object debug { value true } }

commit stay
"""

import json, time

# main entry function for event handler
def event_handler_main(in_json_str):
    # parse input json string passed by event handler
    in_json = json.loads(in_json_str)
    paths = in_json["paths"]
    options = in_json["options"]
    data = in_json["persistent-data"] if "persistent-data" in in_json else {}

    if options.get("debug") == "true":
       print( in_json_str )

    response_actions = []
    for p in paths:
      if p['value'] == "start":
        path_parts = p['path'].split(' ')
        neighbor_ip = path_parts[5]

        response_actions += [
         # Since we can only configure leaf nodes, set a policer
         {
          "set-cfg-path": {
             "path": "acl policers system-cpu-policer bgp peak-packet-rate",
             "value": "100",
          }
         },
         {
          "set-cfg-path": {
             "path": "/acl cpm-filter ipv4-filter entry 123 match protocol",
             "value": "tcp",
          }
         },
         {
          "set-cfg-path": {
             "path": "/acl cpm-filter ipv4-filter entry 123 match source-ip prefix",
             "value": f"{neighbor_ip}/32",
          }
         },
         {
          "set-cfg-path": {
             "path": "/acl cpm-filter ipv4-filter entry 123 match destination-port operator",
             "value": "eq",
          }
         },
         {
          "set-cfg-path": {
             "path": "/acl cpm-filter ipv4-filter entry 123 match destination-port value",
             "value": "179",
          }
         },
         {
          "set-cfg-path": {
             "path": "/acl cpm-filter ipv4-filter entry 123 action accept rate-limit system-cpu-policer",
             "value": "bgp",
          }
         },
        ]

    response = {"actions": response_actions, "persistent-data": data }
    return json.dumps(response)
