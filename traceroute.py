from scapy.all import *
from scapy.layers.inet import ICMP, IP


def traceroute(destination):
    ttl = 1
    max_hops = 30  # Maximum number of hops to try

    while True:
        # Craft the packet with increasing TTL
        packet = IP(dst=destination, ttl=ttl) / ICMP()

        # Send the packet and receive the response
        reply = sr1(packet, verbose=0, timeout=1)

        if reply is None:
            # No response received within the timeout
            print(f"{ttl}. * * *")
        elif reply.type == 0:
            # Destination reached, ICMP Echo Reply received
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
destination = "www.google.com"

# Perform traceroute
traceroute(destination)

# if __name__ == '__main__':
#     print('PyCharm')