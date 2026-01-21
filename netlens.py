import typer
from rich.console import Console

from protocols.arp import arp
from protocols.ethernet import ethernet_frame
from tools.sniffer import Sniffer

app = typer.Typer(add_completion=False)
console = Console()


def handler(packet):
    table = ethernet_frame(packet)
    if not table:
        return
    for parser in (arp,):
        if parser(packet, table):
            console.print(table)
            return


@app.command()
def start(
        interface: str = typer.Option("enp2s0", "--iface", "-i"),
        count: int = typer.Option(0, "--count", "-c"),
        timeout: int = typer.Option(None, "--timeout", "-t"),
):
    Sniffer(interface=interface, count=count, timeout=timeout).start(handler=handler)


if __name__ == "__main__":
    app()
