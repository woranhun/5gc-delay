import pyshark.packet.packet


class UE:

    def __init__(self, suci: int):
        self.packets = []
        self.suci = suci
        self.amf_delay = 0

    def addMessage(self, packet: pyshark.packet.packet.Packet) -> None:
        self.packets.append(packet)

    def displayTimeDeltas(self) -> None:
        for i in range(len(self.packets) - 1):
            p1 = self.packets[i]
            p2 = self.packets[i + 1]
            dt = p2.sniff_time - p1.sniff_time
            self.amf_delay += dt.total_seconds()
        print("SUCI: [{0}] - delay: {1} s".format(self.suci, self.amf_delay))
