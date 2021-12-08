import json
import os
import re

import pyshark

from delaycalculator.UE import UE


class DelayCalculator:

    def __init__(self, capture_path: str):
        if not os.path.exists(capture_path):
            raise RuntimeError("Capture not found!")
        self.cap = pyshark.FileCapture(capture_path, display_filter="ngap || nas-5gs || (http2 && tcp.port==7777)")
        self.UEs = []
        self.stream_ids_33_37 = {}
        self.stream_ids_47_48 = {}
        self.stream_ids_49_50 = {}
        self.amf_total_delay = 0
        # '/nudr-dr/v1/subscription-data/imsi-001010000000002/context-data/amf-3gpp-access'
        self.eventHelix4748PathPattern = re.compile(
            "^/nudr-dr/v1/subscription-data/imsi-[0-9]+/context-data/amf-3gpp-access$")
        # '/nudm-sdm/v2/imsi-001010000000002/am-data'
        self.eventHelix4950PathPattern = re.compile(
            "^/nudm-sdm/v2/imsi-[0-9]+/am-data$")

    def toStreamKey(self, tcpId: int, http2Id: int) -> str:
        return "tcp:{0}-http2:{1}".format(tcpId, http2Id)

    def getTcpFromStreamKey(self, key: str) -> int:
        return int(key.split("-")[0].split(":")[1])

    def getHttp2FromStreamKey(self, key: str) -> int:
        return int(key.split("-")[1].split(":")[1])

    def findUEBySUCI(self, suci: int) -> UE:
        for ue in self.UEs:
            if ue.suci == suci:
                return ue

    def calculate(self) -> None:
        for i, pkt in enumerate(self.cap):
            ngap_layers = [i for i in pkt.layers if i.layer_name == "ngap"]
            if ngap_layers:
                for layer in ngap_layers:
                    if hasattr(layer, 'initialuemessage_element') \
                            and hasattr(layer, 'nas_5gs_mm_message_type') \
                            and int(layer.nas_5gs_mm_message_type) == 65:  # Message type: Registration request (0x41)
                        ue = UE(int(layer.nas_5gs_mm_suci_supi_null_scheme))
                        ue.packets["24"].append(pkt)
                        self.UEs.append(ue)
                    elif hasattr(layer, 'gsm_a_dtap_autn') \
                            and hasattr(layer, 'nas_5gs_mm_message_type') \
                            and int(layer.nas_5gs_mm_message_type) == 86:  # Message type: Authentication request (0x56)
                        for ue in self.UEs:
                            if ue.autn['5gAuthData']['autn'] == str(layer.gsm_a_dtap_autn).replace(':', ''):
                                ue.packets["38"].append(pkt)
                                ue.ran_ue_ngap_id = int(layer.ran_ue_ngap_id)
                                ue.amf_ue_ngap_id = int(layer.amf_ue_ngap_id)
                    elif hasattr(layer, 'uplinknastransport_element') \
                            and hasattr(layer, 'nas_5gs_mm_message_type') \
                            and int(layer.nas_5gs_mm_message_type) == 87:  # Message type: Authentication request (0x57)
                        for ue in self.UEs:
                            if ue.amf_ue_ngap_id == int(layer.amf_ue_ngap_id):
                                ue.packets["39"].append(pkt)
                    elif hasattr(layer, 'downlinknastransport_element') \
                            and hasattr(layer, 'nas_5gs_security_header_type') \
                            and int(layer.nas_5gs_security_header_type) == 3:
                        for ue in self.UEs:
                            if ue.amf_ue_ngap_id == int(layer.amf_ue_ngap_id):
                                ue.packets["40"].append(pkt)

            elif pkt.highest_layer == 'HTTP2' \
                    and hasattr(pkt.http2, 'header') \
                    and str(pkt.http2.header) == 'Header: :method: POST' \
                    and str(pkt.http2.headers_path) == '/nausf-auth/v1/ue-authentications':
                self.stream_ids_33_37[self.toStreamKey(
                    int(pkt.tcp.stream), int(pkt.http2.streamid))] = [None, 1]  # header + data + rspheader + rspdata
            elif pkt.highest_layer == 'HTTP2' \
                    and hasattr(pkt.http2, 'streamid') \
                    and self.toStreamKey(int(pkt.tcp.stream),
                                         int(pkt.http2.streamid)) in self.stream_ids_33_37.keys() \
                    and str(pkt.http2.DATA_LAYER) == 'data' \
                    and self.stream_ids_33_37[self.toStreamKey(int(pkt.tcp.stream),
                                                               int(pkt.http2.streamid))][1] == 1:
                jsonstr = bytes.fromhex(str(pkt.http2.data_data).replace(':', '')).decode("ASCII")
                if 'supiOrSuci' in jsonstr:
                    suci = json.loads(jsonstr)[
                        'supiOrSuci']
                    self.findUEBySUCI(int(suci.split('-')[-1])).packets["33"].append(pkt)
                    self.stream_ids_33_37[self.toStreamKey(int(pkt.tcp.stream),
                                                           int(pkt.http2.streamid))] = [suci, 2]
            elif pkt.highest_layer == 'HTTP2' \
                    and hasattr(pkt.http2, 'streamid') \
                    and self.toStreamKey(int(pkt.tcp.stream),
                                         int(pkt.http2.streamid)) in self.stream_ids_33_37.keys():
                self.stream_ids_33_37[self.toStreamKey(int(pkt.tcp.stream),
                                                       int(pkt.http2.streamid))][1] += 1
                ue = self.findUEBySUCI(int(self.stream_ids_33_37[self.toStreamKey(int(pkt.tcp.stream),
                                                                                  int(pkt.http2.streamid))][0].split(
                    '-')[-1]))
                ue.packets["37"].append(pkt)
                if self.stream_ids_33_37[self.toStreamKey(int(pkt.tcp.stream),
                                                          int(pkt.http2.streamid))][1] == 4:
                    ue.autn = json.loads(bytes.fromhex(str(pkt.http2.data_data).replace(':', '')).decode("ASCII"))
            elif pkt.highest_layer == 'HTTP2' \
                    and hasattr(pkt.http2, 'header') \
                    and str(pkt.http2.header) == 'Header: :method: PUT' \
                    and self.eventHelix4748PathPattern.match(str(pkt.http2.headers_path)):
                imsi = str(pkt.http2.headers_path).split('/')[4].split('-')[1]
                suci = int(imsi[len(imsi) - 10:])
                ue = self.findUEBySUCI(suci)
                ue.packets["47"].append(pkt)
                self.stream_ids_47_48[self.toStreamKey(int(pkt.tcp.stream), int(pkt.http2.streamid))] = [suci, 1]
            elif pkt.highest_layer == 'HTTP2' \
                    and hasattr(pkt.http2, 'streamid') \
                    and self.toStreamKey(int(pkt.tcp.stream),
                                         int(pkt.http2.streamid)) in self.stream_ids_47_48.keys():
                stream = self.stream_ids_47_48[self.toStreamKey(int(pkt.tcp.stream),
                                                                int(pkt.http2.streamid))]
                ue = self.findUEBySUCI(stream[0])
                if stream[1] == 1:
                    ue.packets["47"].append(pkt)
                    self.stream_ids_47_48[self.toStreamKey(int(pkt.tcp.stream), int(pkt.http2.streamid))] = [stream[0],
                                                                                                             2]
                elif stream[1] == 2:
                    ue.packets["48"].append(pkt)
                    self.stream_ids_47_48[self.toStreamKey(int(pkt.tcp.stream), int(pkt.http2.streamid))] = [stream[0],
                                                                                                             3]
            elif pkt.highest_layer == 'HTTP2' \
                    and hasattr(pkt.http2, 'header') \
                    and str(pkt.http2.header) == 'Header: :method: GET' \
                    and self.eventHelix4950PathPattern.match(str(pkt.http2.headers_path)):
                imsi = str(pkt.http2.headers_path).split('/')[3].split('-')[1]
                suci = int(imsi[len(imsi) - 10:])
                ue = self.findUEBySUCI(suci)
                ue.packets["49"].append(pkt)
                self.stream_ids_49_50[self.toStreamKey(int(pkt.tcp.stream), int(pkt.http2.streamid))] = [suci, 1]
            elif pkt.highest_layer == 'HTTP2' \
                    and hasattr(pkt.http2, 'streamid') \
                    and self.toStreamKey(int(pkt.tcp.stream),
                                         int(pkt.http2.streamid)) in self.stream_ids_49_50.keys():
                stream = self.stream_ids_49_50[self.toStreamKey(int(pkt.tcp.stream),
                                                                int(pkt.http2.streamid))]
                ue = self.findUEBySUCI(stream[0])
                if stream[1] == 1:
                    ue.packets["49"].append(pkt)
                    self.stream_ids_49_50[self.toStreamKey(int(pkt.tcp.stream), int(pkt.http2.streamid))] = [stream[0],
                                                                                                             2]
                elif stream[1] == 2:
                    ue.packets["50"].append(pkt)
                    self.stream_ids_49_50[self.toStreamKey(int(pkt.tcp.stream), int(pkt.http2.streamid))] = [stream[0],
                                                                                                             3]

        for ue in self.UEs:
            ue.displayTotalDelay()
            self.amf_total_delay += ue.amf_delay
            print("TOTAL delay for AMF: {0:0.6f} s".format(self.amf_total_delay))
