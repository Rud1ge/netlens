from rich.console import Console
from rich.table import Table
from scapy.layers.l2 import ARP, Ether


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
        table.add_row("Ethernet", "Source MAC Address", {len(bytes(eth.src))}, f"{eth.src}")
        table.add_row("Ethernet", "Destination MAC Address", "6 bytes", f"{eth.dst}")
        table.add_row("Ethernet", "EtherType", "2 bytes", f"{hex(eth.type)}")

    console = Console()
    console.print(table)
