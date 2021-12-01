import os

import pyshark

from delaycalculator.UE import UE


class DelayCalculator:

    def __init__(self, capture_path: str):
        if not os.path.exists(capture_path):
            raise RuntimeError("Capture not found!")
        self.cap = pyshark.FileCapture(capture_path, display_filter="ngap || nas-5gs || (http2 && tcp.port==7777)")
        self.UEs = []
        self.important_stream_ids = []

    def findUEBySUCI(self, suci: int) -> UE:
        for ue in self.UEs:
            if ue.suci == suci:
                return ue

    def calculate(self) -> None:
        for pkt in self.cap:

            if pkt.highest_layer == 'NGAP' and hasattr(pkt.ngap, 'initialuemessage_element') and int(
                    pkt.ngap.nas_5gs_mm_message_type) == 65:  # Message type: Registration request (0x41)
                ue = UE(int(pkt.ngap.nas_5gs_mm_suci_supi_null_scheme))
                ue.packets.append(pkt)
                self.UEs.append(ue)

            elif pkt.highest_layer == 'HTTP2' \
                    and hasattr(pkt.http2, 'header') \
                    and str(pkt.http2.header) == 'Header: :method: POST' \
                    and str(pkt.http2.headers_path) == '/nausf-auth/v1/ue-authentications':
                self.important_stream_ids.append(int(pkt.http2.streamid))
            elif pkt.highest_layer == 'HTTP2' \
                    and hasattr(pkt.http2, 'streamid') \
                    and int(pkt.http2.streamid) in self.important_stream_ids \
                    and str(pkt.http2.DATA_LAYER) == 'data' \
                    and hasattr(pkt.http2, 'json_value_string'):
                if 'suci' in str(pkt.http2.json_value_string):
                    self.findUEBySUCI(int(str(pkt.http2.json_value_string).split('-')[-1])).packets.append(pkt)
                    self.important_stream_ids.remove(int(pkt.http2.streamid))
                else:
                    print("SUCI helyett: " + str(pkt.highest_layer.http2.json_value_string))

        for ue in self.UEs:
            ue.displayTimeDeltas()
