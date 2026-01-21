from rich.console import Console
from rich.table import Table
from scapy.layers.l2 import ARP, Ether
from scapy.utils import mac2str
import struct


def arp(packet):
    if not packet.haslayer(ARP):
        return

    table = Table(title=f"Address Resolution Protocol", title_justify="left")
    table.add_column("Layer")
    table.add_column("Field")
    table.add_column("Weight")
    table.add_column("Value")

    eth = packet.getlayer(Ether)
    if eth:
        table.add_row("Ethernet", "Source MAC Address", f"{len(mac2str(eth.src))} bytes", f"{eth.src}")
        table.add_row("Ethernet", "Destination MAC Address", f"{len(mac2str(eth.dst))} bytes", f"{eth.dst}")
        table.add_row("Ethernet", "EtherType", f"{len(struct.pack('!H', int(eth.type)))} bytes", f"{hex(eth.type)}")

    console = Console()
    console.print(table)
