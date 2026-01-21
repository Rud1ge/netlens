from scapy.compat import raw
from scapy.layers.l2 import ARP

arp_hwtype = {
    1: "Ethernet",
    6: "IEEE 802",
    15: "Frame Relay",
    16: "ATM",
    19: "ATM",
    20: "Serial Line",
    24: "IEEE 1394",
    27: "EUI-64",
    32: "InfiniBand",
}

arp_ptype = {0x0800: "IPv4", 0x86DD: "IPv6"}

arp_op = {
    1: "request",
    2: "reply",
    3: "RARP request",
    4: "RARP reply",
    8: "InARP request",
    9: "InARP reply",
}


def arp(packet, table):
    if ARP not in packet:
        return False

    arp_layer = packet[ARP]

    hwtype = int(arp_layer.hwtype)
    ptype = int(arp_layer.ptype)
    op = int(arp_layer.op)

    table.add_row("ARP", "Hardware type", "16", f"{hwtype} ({arp_hwtype[hwtype]})")
    table.add_row("ARP", "Protocol type", "16", f"{hex(ptype)} ({arp_ptype[ptype]})")
    table.add_row("ARP", "Hardware size", "8", str(int(arp_layer.hwlen)))
    table.add_row("ARP", "Protocol size", "8", str(int(arp_layer.plen)))
    table.add_row("ARP", "Operation", "16", f"{op} ({arp_op[op]})")
    table.add_row("ARP", "Sender MAC", str(int(arp_layer.hwlen) * 8), str(arp_layer.hwsrc))
    table.add_row("ARP", "Sender IP", str(int(arp_layer.plen) * 8), str(arp_layer.psrc))
    table.add_row("ARP", "Target MAC", str(int(arp_layer.hwlen) * 8), str(arp_layer.hwdst))
    table.add_row("ARP", "Target IP", str(int(arp_layer.plen) * 8), str(arp_layer.pdst))

    actual_bytes = len(raw(arp_layer)) - len(raw(arp_layer.payload))
    table.caption = f"ARP PDU length: {actual_bytes * 8} bits ({actual_bytes} bytes)"
    table.caption_justify = "left"

    return True
