import argparse
from scapy.utils import rdpcap
from sni_bytes import get_tls_from_crypto
from hwcounter import Timer

def main(pcap_file):
    pcap_data = rdpcap(pcap_file)
    cycles = []
    for pkt in pcap_data:
        try:
            with Timer() as t_total:
                packet_bytes = bytes(pkt)

                packet_bytes = bytes(pkt)
                next_index = 14 #Skip Eth Layer

                # IP Layer Processing
                version = (packet_bytes[next_index] & 0xF0) >> 4
                if version != 4: # Not handling IPv6
                    continue
                hlen = packet_bytes[next_index] & 0x0F
                tos = packet_bytes[next_index+1]
                total_length = packet_bytes[next_index+2: next_index+4]
                
                identification = packet_bytes[next_index+4: next_index+6]
                flags_and_fragment_offset = packet_bytes[next_index+6: next_index+8]

                ttl = packet_bytes[next_index+8]
                protocol = packet_bytes[next_index+9]
                checksum = packet_bytes[next_index+10:next_index+12]

                source_ip = packet_bytes[next_index+12: next_index+16]
                dest_ip = packet_bytes[next_index+16: next_index+20]

                if protocol != 6: # Denotes TCPP
                    continue

                next_index += hlen * 4 # Skip Options

                # TCP Processing
                
                src_port = packet_bytes[next_index: next_index+2]
                dst_port = packet_bytes[next_index+2: next_index+4]
        
                seq_num = packet_bytes[next_index+4: next_index+8]

                ack_num = packet_bytes[next_index+8: next_index+12]

                hlen = (packet_bytes[next_index+12] & 0xF0) >> 4
                flags = packet_bytes[next_index+13] & 0x3F
                window_size = packet_bytes[next_index+14: next_index:16]

                checksum = packet_bytes[next_index+16: next_index:18]
                urg_pointer = packet_bytes[next_index+18: next_index+20]

                next_index += hlen * 4 # Skip Options

                # TLS Processing

                content_type = packet_bytes[next_index]
                if content_type != 22: # Handshake
                    continue

                version = packet_bytes[next_index+1: next_index+3]
                length = packet_bytes[next_index+3: next_index+5]
                
                # Client Hello Processing
                next_index = next_index+5
                with Timer() as t_sni:
                    sni = get_tls_from_crypto(packet_bytes[next_index:])

                print(sni)
        except Exception as e:
            print("Exception:", e)
            continue    
        cycles.append((t_total.cycles, t_sni.cycles))

    count = 0
    with open("cycles_tcp.csv", "w") as f:
        for c in cycles:
            identify = c[0] - c[1]
            sni = c[1]
            if c[0]>80000:
                print("skipped :", count)
                count+=1
                continue
            f.write(str(identify) +"," + str(sni)+ "\n")

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", help = "Pcap file to be analyzed")
    args = parser.parse_args()
    pcap_file = args.file
    main(pcap_file)


