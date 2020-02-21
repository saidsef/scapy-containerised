#!/bin/env python3

import json
from scapy.all import *
from scapy.utils import *
from scapy.layers import http

load_layer('tls')

def sniffer(packet):
    if packet.haslayer(Raw):
        r = packet.getlayer(Raw).load
        try:
            p = json.loads(r)
            print(p)
        except:
            pass

sniff(iface="en0", prn=sniffer)