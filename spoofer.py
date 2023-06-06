from scapy.all import *
from scapy.layers.inet import IP, ICMP, UDP, TCP
import random

# a = IP()  # create an IP object
# a.dst = '10.0.2.3'
# b = ICMP()
# p = a/b
# send(p)

# Function to spoof ICMP packets
def spoof_icmp(target_ip, source_ip):
    icmp = ICMP()
    ip = IP(dst=target_ip, src=source_ip)
    packet = ip / icmp
    send(packet)

# Function to spoof UDP packets
def spoof_udp(target_ip, target_port, source_ip, source_port):
    udp = UDP(dport=target_port, sport=source_port)
    ip = IP(dst=target_ip, src=source_ip)
    packet = ip / udp
    send(packet)

# Function to spoof TCP packets
def spoof_tcp(target_ip, target_port, source_ip, source_port):
    seq_num = random.randint(1000, 9000)
    ack_num = 0
    tcp = TCP(dport=target_port, sport=source_port, flags="S", seq=seq_num, ack=ack_num)
    ip = IP(dst=target_ip, src=source_ip)
    packet = ip / tcp
    send(packet)


# Specify the target IP and port
target_ip = "192.168.0.100"  # Replace with the target IP address
target_port = 1234  # Replace with the target port number

# Specify the source IP and port for spoofing
source_ip = "10.0.0.1"  # Replace with the desired source IP address
source_port = 5678  # Replace with the desired source port number

# Spoof ICMP packet
spoof_icmp(target_ip, source_ip)

# Spoof UDP packet
spoof_udp(target_ip, target_port, source_ip, source_port)

# Spoof TCP packet
spoof_tcp(target_ip, target_port, source_ip, source_port)


# if __name__ == '__main__':
#     print('PyCharm')