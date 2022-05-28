#!/bin/env python3

import json
import logging
from scapy.all import *
from scapy.utils import *
from scapy.layers import http

load_layer('tls')

def sniffer(packet):
  '''Takes raw packets and prints packet as string'''
  if packet.haslayer(Raw):
    r = packet.getlayer(Raw).load
    try:
      p = json.loads(r)
      print(p)
    except Exception as e:
      logging.error(e)
      pass

sniff(iface="en0", prn=sniffer)
