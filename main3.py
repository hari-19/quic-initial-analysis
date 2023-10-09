import pyshark
import argparse
from binascii import unhexlify
from hwcounter import Timer
import hkdf
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from sni_bytes import extract_sni
from scapy.utils import rdpcap

initial_salt = unhexlify("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
client_in = unhexlify("00200f746c73313320636c69656e7420696e00")
quic_key = unhexlify("00100e746c7331332071756963206b657900")
quic_iv = unhexlify("000c0d746c733133207175696320697600")
quic_hp = unhexlify("00100d746c733133207175696320687000")

def main(pcap_file):
    pcap_data = rdpcap(pcap_file)
    cycles = []
    i = 0
    for pkt in pcap_data:
        try:
            with Timer() as t_total:
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

                if protocol != 17: # Denotes UDP
                    continue

                next_index += hlen * 4 # Skip Options

                # UDP Header Processing
                src_port = packet_bytes[next_index: next_index+2]
                dst_port = packet_bytes[next_index+2: next_index+4]
                length = packet_bytes[next_index+4: next_index+6]
                checksum = packet_bytes[next_index+6: next_index+8]

                next_index += 8

                # QUIC Processing

                udp_payload = packet_bytes[next_index:]
                    
                '''
                Start of the QUIC Dissector

                Initial Packet contains following structure
                
                Header Form (1) = 1,
                Fixed Bit (1) = 1,
                Long Packet Type (2) = 0,
                Reserved Bits (2),
                Packet Number Length (2),
                Version (32),
                Destination Connection ID Length (8),
                Destination Connection ID (0..160),
                Source Connection ID Length (8),
                Source Connection ID (0..160),
                Token Length (i),
                Token (..),
                Length (i),
                Packet Number (8..32),
                Packet Payload (8..),
                '''

        
                # flag byte (1B) + version (4B) + DCID len (1B) + SCID len (1B) = 7B
                if len(udp_payload) <= 7:
                    # not a QUIC Long Header Packet
                    continue 
                
                # Header Form Check
                if (udp_payload[0] & 0x80 != 0x80):
                    continue

                # Fixed Bit Check
                if (udp_payload[0] & 0x40 != 0x40):
                    continue

                # Packet Type Check
                if (udp_payload[0] & 0x30 != 0):
                    # Not a Initial Packet
                    continue
                
                # Check QUIC Version
                version = udp_payload[1:5]
                if(int.from_bytes(version, "big") != 0x1):
                    print("Version Mismatch")

                dcid_len = udp_payload[5]
                
                next_index = 6
                
                dcid = udp_payload[next_index: next_index + dcid_len]
                next_index += dcid_len

                scid_len = udp_payload[next_index]
                next_index +=1 

                scid = udp_payload[next_index: next_index + scid_len]
                next_index += scid_len

                token_len = udp_payload[next_index]
                next_index += 1 + token_len # Skip token
                
                len_msb = (udp_payload[next_index] & 0xc0) >> 6
                if len_msb == 0x0:
                    len_of_length = 1
                elif len_msb == 0x1:
                    len_of_length = 2
                elif len_msb == 0x2:
                    len_of_length = 4
                else:
                    len_of_length = 8

                first_byte = (udp_payload[next_index] & 0x3f).to_bytes(1, "big")
                len_bytes = first_byte + udp_payload[next_index+1: next_index+len_of_length]
                
                with Timer() as t_decrypt:
                    # Length of payload
                    payload_len = int.from_bytes(len_bytes, "big")
                    next_index+=len_of_length

                    # Decryption Keys 
                    initial_secret = hkdf.hkdf_extract(initial_salt, dcid, hash=hashlib.sha256)
                    client_initial_secret = hkdf.hkdf_expand(initial_secret, client_in, 32, hash=hashlib.sha256)
                    
                    # HP uses AES-ECB 
                    hp = hkdf.hkdf_expand(client_initial_secret, quic_hp, 16, hash=hashlib.sha256)
                    cipher = Cipher(algorithm=algorithms.AES(hp), mode=modes.ECB())
                    encryptor = cipher.encryptor()
                    # Sample is always 16B starting with 4B offset from the PKN.
                    sample  = udp_payload[next_index+4: next_index+20]
                    header_mask = encryptor.update(sample) + encryptor.finalize()
                    pkn_len = (udp_payload[0] ^ (header_mask[0] & 0x0f)) & 0x03
                                                                        
                    # Retrive the PKN
                    pkn = int.from_bytes(udp_payload[next_index: next_index+pkn_len+1], "big") ^ int.from_bytes(header_mask[1:pkn_len+2], "big")
                    next_index += pkn_len + 1
                    
                    with Timer() as t_payload:
                        payload_len -= pkn_len+1
                        payload = udp_payload[next_index: next_index+payload_len]

                        key = hkdf.hkdf_expand(client_initial_secret, quic_key, 16, hash=hashlib.sha256)
                        iv = hkdf.hkdf_expand(client_initial_secret, quic_iv, 12, hash=hashlib.sha256)

                        nonce = pkn ^ int.from_bytes(iv, "big")
                        nonce = nonce.to_bytes(12, "big")

                        tag = payload[-16:]
                        payload = payload[:-16]
                        
                        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=None)
                        decryptor = cipher.decryptor()
                        decrypted_payload = decryptor.update(payload)
                        # sni = extract_sni(hexlify(decrypted_payload))
                        with Timer() as t_sni:
                            sni = extract_sni(decrypted_payload)
                    
        except Exception as e:
            continue
        cycles.append((t_total.cycles, t_decrypt.cycles, t_payload.cycles, t_sni.cycles))
        break

    count= 0
    with open("cycles_out.csv", "w") as f:
        for c in cycles:
            if c[0]>800000:
                print("skipped :", count)
                count+=1
                continue
            identify = c[0] - c[1]
            hp = c[1] - c[2]
            payload = c[2] - c[3]
            sni = c[3]

            f.write(str(identify) +","+ str(hp) +"," +str(payload) +"," + str(sni)+ "\n")


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", help = "Pcap file to be analyzed")
    args = parser.parse_args()
    pcap_file = args.file
    main(pcap_file)
