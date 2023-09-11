import pyshark
from scapy.all import *
from quic import sni_quic_extract_custom

i = 0
def callback(packet):
    global i
    try:
        if packet['quic'].long.packet_type == '0': # 0 is for Initial Packet frame
            sni = sni_quic_extract_custom(packet)
            if sni == "NA":
                return
            else:
                print(i, ": ", sni)
            i+=1
            new_cap = PcapWriter("./new3.pcap", append=True)
            new_cap.write(packet.get_raw_packet())
            if(i >= 819):
                print("QUIT")
                exit(0)
    except Exception as e:
        pass

capture = pyshark.LiveCapture(include_raw=True, output_file="i.pcap", use_json=True, )
capture.apply_on_packets(callback)
capture.sniff()