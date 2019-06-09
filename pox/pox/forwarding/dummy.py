# Copyright 2012 James McCauley
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
A very dumb controller that always floods packets.
"""

from pox.core import core
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4
import pox.openflow.libopenflow_01 as of
from pox.triton.cannon import Cannon
import re

# Even a simple usage of the logger is much nicer than print!
log = core.getLogger()

TARGET_DOMAIN_RE = re.compile(r'^blink.ucsd.edu$', re.I)
URL_PATH_RE = re.compile(r'^/~bjohhnne', re.I)
IFRAME_URL = 'http://cryptosec.ucsd.edu'

# This handler will see every packet the switch receives 
# since there are (will not be) any rules in the switch
def _handle_PacketIn (event):
    packet = event.parsed
    ip_packet = packet.find('ipv4')
    drop_packet = False
    if isinstance(packet, ethernet) and (ip_packet is not None):
	new_ip_packet = core.Cannon.manipulate_packet(ip_packet)

	# Drop packet	
	if not isinstance(new_ip_packet, ipv4):
            if new_ip_packet is None:
	        log.info("Packet dropped.")
	    else:
		log.info("Return value of manipulate_packet is not an instance of ipv4 class. Packet dropped.")
	    msg = of.ofp_packet_out(data = event.ofp)	
      	    drop_packet = True
	else:
            # Use the return value of manipulate_packet as the new payload of the ethernet packet
	    packet.payload = new_ip_packet
	    msg = of.ofp_packet_out(in_port = event.port, data = packet)
    else:
	# Send back the original packet
	msg = of.ofp_packet_out(data = event.ofp)

    if not drop_packet:
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))

    # Send msg to the switch	
    event.connection.send(msg)
    
def launch ():
    if core.hasComponent('openflow'):
    	core.openflow.miss_send_len = 0x7fff
    	log.info("Requesting full packet payloads")
    else:
	log.info("No openflow component")
	return

    core.registerNew(Cannon, TARGET_DOMAIN_RE, URL_PATH_RE, IFRAME_URL)
    core.openflow.addListenerByName("PacketIn", _handle_PacketIn)
    log.info("Dumb controller is running.")
