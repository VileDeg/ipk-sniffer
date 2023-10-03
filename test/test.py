import sys
from scapy.all import *
import scapy.contrib.igmp

# get destination port from command line arguments
dest_port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
eth0_addr = "172.18.91.60" # on my machine, eth0 has this address

pkts = [
    IPv6(src= "fe80::215:5dff:febb:fc75", dst="fe80::90ce:1827:6881:6899", nh=58) 
        / ICMPv6EchoRequest(id=2222, seq=3333) / "Hello, world!", # ICMPv6

    Ether(dst="ff:ff:ff:ff:ff:ff") / 
        ARP(op=1, hwsrc="FF:FF:FF:FF:FF:FF", psrc="192.168.1.1", pdst="192.168.1.2"), # ARP

    IP(dst="224.0.0.1") / scapy.contrib.igmp.IGMP(), # IGMP

    IPv6(dst='fe80::1234') / ICMPv6ND_RS() / ICMPv6NDOptSrcLLAddr(lladdr='01:23:45:67:89:ab'), # NDP

    IPv6(dst="ff02::16") / ICMPv6MLQuery(mladdr="ff02::1:2"), # MLD

    IP(dst=eth0_addr) / ICMP() / "Hello, world!", # ICMPv4

    IP(dst=eth0_addr) / UDP(sport=RandShort(), dport=dest_port) / "Hello, world!", # UDP

    IP(dst=eth0_addr) / TCP(sport=RandShort(), dport=dest_port) / "Hello, world!" # TCP
]

# send the packets
send(pkts)
