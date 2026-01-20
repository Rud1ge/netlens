import typer

from protocols.arp import arp
from tools.sniffer import Sniffer

app = typer.Typer(add_completion=False)


def handler(packet):
    arp(packet)


@app.command()
def start(
        interface: str = typer.Option("enp2s0", "--iface", "-i"),
        count: int = typer.Option(0, "--count", "-c"),
        timeout: int = typer.Option(None, "--timeout", "-t"),
):
    Sniffer(interface=interface, count=count, timeout=timeout).start(handler=handler)


if __name__ == "__main__":
    app()
