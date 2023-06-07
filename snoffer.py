from scapy.all import *
from scapy.layers.inet import IP, ICMP

def sniff_icmp_Lan():
    sniff(filter='icmp', prn=spoof_icmp_Lan)


def spoof_icmp_Lan(packet):
    icmp = ICMP(type=0)  # 0 means echo reply
    ip = IP(dst=packet[IP].src, src=packet[IP].dst)  # Pretending to be the receiver's response
    sn = ip / icmp
    print(sn)
    send(sn)
#
# spoof_icmp(target_ip, source_ip)