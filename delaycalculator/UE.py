import pyshark.packet.packet


class UE:

    def __init__(self, suci: int):
        self.packets = {key: list() for key in ["24", "33", "37", "38", "39", "40", "41",
                                                "47", "48", "49", "50", "51", "52", "60", "61", "76"]}

        self.suci = suci
        self.autn = None
        self.ran_ue_ngap_id = 0
        self.amf_ue_ngap_id = 0

        self.amf_delay = 0

    def addMessage(self, packet: pyshark.packet.packet.Packet, evetHelixId: int) -> None:
        self.packets[evetHelixId] = packet

    def calculateDeltaT(self, p1: pyshark.packet.packet.Packet, p2: pyshark.packet.packet.Packet) -> float:
        dt = p2.sniff_time - p1.sniff_time
        return dt.total_seconds()

    def Calculate_24_33(self) -> None:
        dt = self.calculateDeltaT(self.packets["24"][0], self.packets["33"][0])
        self.amf_delay += dt
        print("SUCI: [{0}] - EventHelix 24 and 33 - delay: {1:0.6f} s".format(self.suci, dt))

    def Calculate_37_38(self) -> None:
        dt = self.calculateDeltaT(self.packets["37"][0], self.packets["37"][1])
        dt += self.calculateDeltaT(self.packets["37"][1], self.packets["38"][0])
        self.amf_delay += dt
        print("SUCI: [{0}] - EventHelix 37 and 38 - delay: {1:0.6f} s".format(self.suci, dt))

    def Calculate_39_40(self) -> None:
        dt = self.calculateDeltaT(self.packets["39"][0], self.packets["40"][0])
        self.amf_delay += dt
        print("SUCI: [{0}] - EventHelix 39 and 40 - delay: {1:0.6f} s".format(self.suci, dt))

    def Calculate_41_47(self) -> None:
        dt = self.calculateDeltaT(self.packets["41"][0], self.packets["47"][0])
        self.amf_delay += dt
        print("SUCI: [{0}] - EventHelix 41 and 47 - delay: {1:0.6f} s".format(self.suci, dt))

    def Calculate_48_49(self) -> None:
        dt = self.calculateDeltaT(self.packets["48"][0], self.packets["49"][0])

        dt += self.calculateDeltaT(self.packets["49"][0], self.packets["49"][1])
        self.amf_delay += dt
        print("SUCI: [{0}] - EventHelix 48 and 49 - delay: {1:0.6f} s".format(self.suci, dt))

    def Calculate_50_51(self) -> None:
        dt = self.calculateDeltaT(self.packets["50"][0], self.packets["51"][0])
        self.amf_delay += dt
        print("SUCI: [{0}] - EventHelix 50 and 51 - delay: {1:0.6f} s".format(self.suci, dt))

    def Calculate_52_60(self) -> None:
        dt = self.calculateDeltaT(self.packets["52"][0], self.packets["52"][1])
        dt += self.calculateDeltaT(self.packets["52"][1], self.packets["60"][0])
        dt += self.calculateDeltaT(self.packets["60"][0], self.packets["60"][1])
        self.amf_delay += dt
        print("SUCI: [{0}] - EventHelix 52 and 60 - delay: {1:0.6f} s".format(self.suci, dt))

    def Calculate_61_76(self) -> None:
        dt = self.calculateDeltaT(self.packets["61"][0], self.packets["61"][1])
        dt += self.calculateDeltaT(self.packets["61"][1], self.packets["76"][0])
        self.amf_delay += dt
        print("SUCI: [{0}] - EventHelix 61 and 76 - delay: {1:0.6f} s".format(self.suci, dt))

    def calculateTotalDelay(self) -> None:
        self.amf_delay = 0
        self.Calculate_24_33()
        self.Calculate_37_38()
        self.Calculate_39_40()
        self.Calculate_41_47()
        self.Calculate_48_49()
        self.Calculate_50_51()
        self.Calculate_52_60()
        self.Calculate_61_76()

    def displayTotalDelay(self) -> None:
        self.calculateTotalDelay()
        print("Total AMF delay for SUCI [{0}] - {1:0.6f} ".format(self.suci, self.amf_delay))
