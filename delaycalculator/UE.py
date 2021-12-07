import pyshark.packet.packet


class UE:

    def __init__(self, suci: int):
        self.packets = {"37": list()}
        self.suci = suci
        self.amf_delay = 0
        self.autn = None
        self.ran_ue_ngap_id = 0
        self.amf_ue_ngap_id = 0

    def addMessage(self, packet: pyshark.packet.packet.Packet, evetHelixId: int) -> None:
        self.packets[evetHelixId] = packet

    def displayTimeDeltas(self, p1: pyshark.packet.packet.Packet, p2: pyshark.packet.packet.Packet) -> float:
        dt = p2.sniff_time - p1.sniff_time
        return dt.total_seconds()

    def Calculate_24_33(self) -> None:
        dt = self.displayTimeDeltas(self.packets["24"],
                                    self.packets["33"])
        self.amf_delay += dt
        print("SUCI: [{0}] - EventHelix 24 and 33 - delay: {1:0.6f} s".format(self.suci,
                                                                              dt))

    def Calculate_37_38(self) -> None:
        dt = self.displayTimeDeltas(self.packets["37"][0],
                                    self.packets["37"][1])
        dt += self.displayTimeDeltas(self.packets["37"][1],
                                     self.packets["38"])
        self.amf_delay += dt
        print("SUCI: [{0}] - EventHelix 37 and 38 - delay: {1:0.6f} s".format(self.suci,
                                                                              dt))

    def Calculate_39_40(self) -> None:
        dt = self.displayTimeDeltas(self.packets["39"],
                                    self.packets["40"])
        self.amf_delay += dt
        print("SUCI: [{0}] - EventHelix 39 and 40 - delay: {1:0.6f} s".format(self.suci,
                                                                              dt))

    def displayTotalDelay(self) -> None:
        self.Calculate_24_33()
        self.Calculate_37_38()
        self.Calculate_39_40()
        print("Total AMF delay for SUCI [{0}] - {1:0.6f} ".format(self.suci, self.amf_delay))
