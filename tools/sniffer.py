from scapy.all import sniff


class Sniffer:
    def __init__(self, interface, count, timeout):
        self.interface = interface
        self.count = count
        self.timeout = timeout

    def start(self, handler):
        try:
            sniff(
                iface=self.interface,
                count=self.count,
                timeout=self.timeout,
                store=False,
                prn=handler,
            )
        except KeyboardInterrupt:
            pass
