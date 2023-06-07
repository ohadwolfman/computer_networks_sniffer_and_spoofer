from scapy.all import *
from scapy.layers.inet import IP, ICMP

def traceroute(destination):
    ttl = 1
    max_hops = 30  # Maximum number of hops to try, to stop messages that may be stuck in a continuous loop

    while True:
        # Craft the packet with increasing TTL
        packet = IP(dst=destination, ttl=ttl) / ICMP()

        # Send the packet and receive the response
        # sometimes it taskes too long to get the response, so we determined timeout =2
        reply = sr1(packet, verbose=0, timeout=2)

        if reply is None:
            # No response received within the timeout
            print(f"{ttl}. * * *")
        elif reply.type == 0:  # I sent ICMP packet from type echo request, 0 means echo reply
            # Destination reached the final destination, ICMP Echo Reply received
            print(f"{ttl}. {reply.src}")
            break
        else:
            # Intermediate hop, ICMP Time Exceeded message received
            print(f"{ttl}. {reply.src}")

        ttl += 1

        if ttl > max_hops:
            # Maximum number of hops reached
            print("Max hops reached.")
            break


# Specify the destination IP address or domain name
destination = "www.ynet.co.il"  # Replace with your desired destination

# Perform traceroute
traceroute(destination)