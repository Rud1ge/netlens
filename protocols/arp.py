import sys

from scapy.layers.l2 import ARP, Ether


def arp(packet):
    if not packet.haslayer(ARP):
        return

    eth = packet.getlayer(Ether)
    if eth:
        sys.stdout.write(f"ARP: ether {eth.src} -> {eth.dst} type={hex(eth.type)}\n")
    else:
        sys.stdout.write("ARP: (no Ether layer)\n")
