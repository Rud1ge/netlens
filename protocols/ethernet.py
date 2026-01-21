from datetime import datetime

from rich.table import Table
from scapy.layers.l2 import Dot1Q, Ether


def ethernet_frame(packet):
    if not packet.haslayer(Ether):
        return None

    table = Table(title=str(datetime.now()), title_justify="left")
    table.add_column("Layer")
    table.add_column("Field")
    table.add_column("Weight (bits)")
    table.add_column("Value")

    eth = packet.getlayer(Ether)
    if eth:
        table.add_row("Ethernet", "Destination MAC Address", "48", str(eth.dst))
        table.add_row("Ethernet", "Source MAC Address", "48", str(eth.src))
        table.add_row("Ethernet", "EtherType", "16", hex(int(eth.type)))

    if packet.haslayer(Dot1Q):
        dot1q = packet.getlayer(Dot1Q)
        table.add_row("Ethernet (802.1Q)", "Priority Code Point (PCP)", "3", str(int(dot1q.prio)))
        table.add_row("Ethernet (802.1Q)", "Drop Eligible Indicator (DEI)", "1", str(int(dot1q.id)))
        table.add_row("Ethernet (802.1Q)", "Virtual Local Area Network ID", "12", str(int(dot1q.vlan)))
        table.add_row("Ethernet (802.1Q)", "Encapsulated EtherType", "16", hex(int(dot1q.type)))

    return table
