import hkdf
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from hwcounter import Timer
from binascii import unhexlify, hexlify
import hashlib

def decrypt_payload(dcid, payload_string,  packet_number):
    initial_salt = "38762cf7f55934b34d179ae6a4c80cadccbb7f0a"
    dcid = dcid.replace(":","")
    payload_string = payload_string.replace(":","")
    
    client_in = "00200f746c73313320636c69656e7420696e00"
    quic_key = "00100e746c7331332071756963206b657900"
    quic_iv = "000c0d746c733133207175696320697600"
    # quic_hp = "00100d746c733133207175696320687000"

    initial_secret = hkdf.hkdf_extract(unhexlify(initial_salt), unhexlify(dcid), hash=hashlib.sha256)
    client_initial_secret = hkdf.hkdf_expand(initial_secret, unhexlify(client_in), 32, hash=hashlib.sha256)
    
    key = hkdf.hkdf_expand(client_initial_secret, unhexlify(quic_key), 16, hash=hashlib.sha256)
    iv = hkdf.hkdf_expand(client_initial_secret, unhexlify(quic_iv), 12, hash=hashlib.sha256)
    # hp = hkdf.hkdf_expand(client_initial_secret, unhexlify(quic_hp), 16, hash=hashlib.sha256)

    iv = hexlify(iv)
    nonce = packet_number ^ int(iv,16)
    nonce = hex(nonce)[2:].zfill(24)
    nonce = unhexlify(nonce)

    tag = unhexlify(payload_string[-32:])
    payload_string = payload_string[:-32]

    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=None)
    
    decryptor = cipher.decryptor()

    final = decryptor.update(unhexlify(payload_string))
    
    return hexlify(final)


def time_quic_decrypt_initial(packet):
    if 'quic' not in packet:
        return None
    
    try:
        if packet['quic'].long_packet_type != '0': # 0 is for Initial Packet frame
            return None
    except Exception as e:
        return None
    
    try:
        dcid = packet['quic'].dcid
    except:
        return None
    
    payload_string = packet['quic'].payload
    packet_number = packet['quic'].packet_number
    
    with Timer() as t:
        decrypt_payload(dcid, payload_string, int(packet_number))

    return t.cycles
    