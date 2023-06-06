import datetime
from scapy.all import *
from scapy.layers.inet import IP, ICMP, UDP, TCP

# Define the filename for the output file
filename = "316552496.txt"


def process_packet(packet):
    if IP in packet:
        source_ip = packet[IP].src
        dest_ip = packet[IP].dst
        source_port = packet.sport
        dest_port = packet.dport
        timestamp = packet.time
        total_length = len(packet)
        cache_flag = b''
        steps_flag = b''
        type_flag = b''
        status_code = b''
        cache_control = b''
        data = b''

        # if raw in packet:
        #     cache_flag = packet[raw].load

        if packet.haslayer(TCP):
            cache_flag = packet[TCP].flags.C
            steps_flag = packet[TCP].flags.E
            type_flag = packet[TCP].flags.U
            status_code = packet[TCP].flags.A
            cache_control = packet[TCP].flags.P
            if hasattr(packet.payload, 'hexdump'):  # Check if hexdump method is available
                data = packet.payload.hexdump()  # Use hexdump instead of hex
            else:
                data = ''  # Set a default value or handle it according to your requirements

        packet_info = {
            "source_ip": source_ip,
            "dest_ip": dest_ip,
            "source_port": source_port,
            "dest_port": dest_port,
            "timestamp": timestamp,
            "total_length": total_length,
            "cache_flag": cache_flag,
            "steps_flag": steps_flag,
            "type_flag": type_flag,
            "status_code": status_code,
            "cache_control": cache_control,
            "data": data
        }

        with open(filename, "a") as file:
            file.write(str(packet_info) + "\n")

def print_the_whole_pkt(pkt):
    pkt.show()


if __name__ == '__main__':
    # filter = "tcp and udp and icmp and igmp"
    # pkt = sniff(filter=filter, prn=print_the_whole_pkt, count = 10)
    sniff(filter="tcp", prn=process_packet)