from scapy.all import *
from scapy.layers.inet import IP, ICMP, UDP, TCP
import random

# a = IP()  # create an IP object
# a.dst = '10.0.2.3'
# b = ICMP()
# p = a/b  # connecting the 2 objects
# send(p)

# Function to spoof ICMP packets
def spoof_icmp(target_ip, source_ip):
    icmp = ICMP()
    ip = IP(dst=target_ip, src=source_ip)
    packet = ip / icmp
    print(packet)
    send(packet)

# Function to spoof UDP packets
def spoof_udp(target_ip, target_port, source_ip, source_port):
    udp = UDP(dport=target_port, sport=source_port)
    ip = IP(dst=target_ip, src=source_ip)
    packet = ip / udp
    print(packet)
    send(packet)

# Function to spoof TCP packets
def spoof_tcp(target_ip, target_port, source_ip, source_port):
    seq_num = random.randint(1000, 9000)
    ack_num = 0
    tcp = TCP(dport=target_port, sport=source_port, flags="S", seq=seq_num, ack=ack_num)
    ip = IP(dst=target_ip, src=source_ip)
    packet = ip / tcp
    print(packet)
    send(packet)


# Specify the target IP and port
target_ip = "192.168.0.100"  # Arbitrary target IP address, it can be replaced
target_port = 1234  # Arbitrary target Port, it can be replaced

# Specify the source IP and port for spoofing
# my source = 10.9.1.43
source_ip = "10.0.0.68"  # The ip I want to spoofing to
source_port = 5678  # Replace with the desired source port number

# Spoof ICMP packet
spoof_icmp(target_ip, source_ip)

# Spoof UDP packet
spoof_udp(target_ip, target_port, source_ip, source_port)

# Spoof TCP packet
spoof_tcp(target_ip, target_port, source_ip, source_port)
